# Oracle TNS/TTC Protocol Description

This document describes the Oracle Net Services protocol as used by
this library. pyoracle communicates with Oracle Database over TCP/IP
(or TLS) using the Transparent Network Substrate (TNS) transport
layer and the Two-Task Common (TTC/TTI) presentation layer.

The structures here were derived clean-room from public artifacts —
python-oracledb's open-source thin-mode implementation (UPL / Apache
2.0), publicly-available reverse-engineering writeups, and packet
captures of authorized Oracle servers. See `CONTRIBUTING.md` for the
sourcing rules. Where the protocol differs between Oracle versions
(notably 11g vs 12c+) the document calls it out per section; pyoracle
is currently validated against Oracle XE 11g.

## 1. Transport Layer: TNS Packets

All communication is framed into TNS packets. Every packet begins with an 8- or 10-byte header depending on type.

### 1.1 Packet Header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Packet Length         |         Packet Flags          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Packet Type  |    Flags      |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Packet Length** (16 bits): Total packet size in bytes, including the header.
- **Packet Flags** (16 bits): Reserved, set to `0x0000`.
- **Packet Type** (8 bits): Identifies the TNS message type (see below).
- **Flags** (8 bits): Reserved, set to `0x00`.
- **Header Checksum** (16 bits): Set to `0x0000`.

For **TNS_DATA** packets (type 6), an additional 2-byte field follows:

- **Data Flags** (16 bits): `0x0000` for a final (or only) packet; `0x0020` when there are more data packets following (fragmented message).

This makes TNS_DATA headers 10 bytes and all other packet headers 8 bytes.

### 1.2 TNS Packet Types

| Value | Name          | Direction      | Description                              |
|-------|---------------|----------------|------------------------------------------|
| 1     | TNS_CONNECT   | Client -> Server | Connection request with connect descriptor |
| 2     | TNS_ACCEPT    | Server -> Client | Connection accepted (SDU negotiated)     |
| 3     | TNS_ACK       | Both           | Acknowledgment                           |
| 4     | TNS_REFUSE    | Server -> Client | Connection refused with error message    |
| 5     | TNS_REDIRECT  | Server -> Client | Redirect to another address              |
| 6     | TNS_DATA      | Both           | Application data (TTC messages)          |
| 7     | TNS_NULL      | Both           | Keep-alive / null message                |
| 9     | TNS_ABORT     | Both           | Abort connection                         |
| 11    | TNS_RESEND    | Server -> Client | Request to resend the last packet        |
| 12    | TNS_MARKER    | Both           | Break / attention marker                 |
| 13    | TNS_ATTENTION | Both           | Attention signal                         |
| 14    | TNS_CONTROL   | Both           | Control message                          |

### 1.3 Packet Fragmentation (SDU)

Messages larger than the Session Data Unit (SDU) are split across multiple TNS_DATA packets. The SDU is negotiated during the connection phase (default: 8192 bytes). When a message is fragmented:

- All fragments except the last have Data Flags set to `0x0020`.
- The last fragment has Data Flags set to `0x0000`.
- The receiver reassembles the full message by concatenating fragment bodies.

## 2. Connection Phase

### 2.1 TNS_CONNECT (Client -> Server)

The client sends a TNS_CONNECT packet containing a fixed header and a connect descriptor string.

**Fixed header fields** (58 bytes before the connect data):

| Offset | Size | Field                        | Default Value     |
|--------|------|------------------------------|-------------------|
| 0      | 2    | Protocol version             | `0x0139` (313)    |
| 2      | 2    | Lowest compatible version    | `0x0139` (313)    |
| 4      | 2    | Global service options       | `0x0000`          |
| 6      | 2    | Session Data Unit (SDU)      | `0x2000` (8192)   |
| 8      | 2    | Transport Data Unit (TDU)    | `0xFFFF` (65535)  |
| 10     | 2    | Protocol characteristics     | `0x4F98`          |
| 12     | 2    | Max packets before ACK       | `0x0000`          |
| 14     | 2    | Hardware byte order          | `0x0001` (big-endian) |
| 16     | 2    | Connect data length          | (computed)        |
| 18     | 2    | Connect data offset          | `0x003A` (58)     |
| 20     | 4    | Max receivable connect data  | `0x00000000`      |
| 24     | 2    | ANO flags                    | `0x8484` (ANO disabled) |
| 26     | 24   | Reserved                     | `0x00...`         |

**Connect descriptor** (at offset 58): An Oracle Net connect descriptor string in the standard `(DESCRIPTION=(...))` format:

```
(DESCRIPTION=
  (CONNECT_DATA=
    (SERVICE_NAME=<service>)
    (CID=(PROGRAM=<app>)(HOST=<client_host>)(USER=<user>)))
  (ADDRESS=
    (PROTOCOL=TCP)
    (HOST=<server_host>)
    (PORT=<port>)))
```

When SSL/TLS is used, `PROTOCOL=TCPS`.

### 2.2 TNS_ACCEPT (Server -> Client)

The server responds with TNS_ACCEPT. The client extracts the negotiated SDU from offset bytes 4-5 (16-bit big-endian) of the accept body. The negotiated SDU is used for all subsequent packet fragmentation.

### 2.3 TNS_REFUSE (Server -> Client)

If the server refuses the connection, it sends TNS_REFUSE with a 4-byte header (2 reserved bytes + 2-byte error length) followed by an error message string.

### 2.4 TNS_REDIRECT (Server -> Client)

The server may redirect the client to a different address. The redirect body contains a connect descriptor with the new `HOST` and `PORT`. The client parses the new address and reconnects.

### 2.5 TNS_RESEND (Server -> Client)

Requests the client to re-send the TNS_CONNECT packet. If using TLS, the client renegotiates the TLS session before resending.

## 3. Presentation Layer: TTC (Two-Task Common)

Once the TNS connection is accepted, all further communication occurs inside TNS_DATA packets using the TTC/TTI protocol. Each TTC message begins with a 1-byte token identifier.

### 3.1 TTC Token Types

| Value | Name    | Description                                |
|-------|---------|--------------------------------------------|
| 1     | TTI_PRO | Protocol negotiation                       |
| 2     | TTI_DTY | Data type negotiation                      |
| 3     | TTI_FUN | Function call (wraps a function ID)        |
| 4     | TTI_OER | Oracle error response                      |
| 6     | TTI_RXH | Row transfer header                        |
| 7     | TTI_RXD | Row data                                   |
| 8     | TTI_RPA | Return parameter (key-value pairs)         |
| 9     | TTI_STA | Status (transaction complete)              |
| 10    | TTI_ROW | Row descriptor                             |
| 11    | TTI_IOV | I/O vector (bind direction indicator)      |
| 12    | TTI_UDS | User describe information                  |
| 13    | TTI_OAC | Oracle Access Column descriptor            |
| 14    | TTI_LOB | LOB data                                   |
| 15    | TTI_WRN | Warning message                            |
| 16    | TTI_DCB | Describe information (column metadata)     |
| 17    | TTI_PFN | Piggyback function                         |
| 19    | TTI_FOB | Flush out binds                            |
| 21    | TTI_BVC | Bit vector for changed columns             |

### 3.2 TTC Function IDs (TTI_FUN)

Function calls are sent as `TTI_FUN` messages with a function ID byte:

| Value | Name         | Description                        |
|-------|--------------|------------------------------------|
| 2     | TTI_OPEN     | Open cursor                        |
| 4     | TTI_EXEC     | Execute statement                  |
| 5     | TTI_FETCH    | Fetch rows                         |
| 9     | TTI_LOGOFF   | Log off                            |
| 14    | TTI_COMMIT   | Commit transaction                 |
| 15    | TTI_ROLLBACK | Rollback transaction               |
| 20    | TTI_CANCEL   | Cancel operation                   |
| 48    | TTI_STRT     | Startup database                   |
| 49    | TTI_STOP     | Shutdown database                  |
| 59    | TTI_VERSION  | Get server version                 |
| 71    | TTI_ALL7     | Generic execute (Oracle 7)         |
| 81    | TTI_3LOGON   | O3LOGON authentication (legacy)    |
| 82    | TTI_3LOGA    | O3LOGON response                   |
| 94    | TTI_ALL8     | Generic execute (Oracle 8+)        |
| 96    | TTI_LOBOPS   | LOB operations                     |
| 103   | TTI_TXSE     | Transaction start                  |
| 104   | TTI_TXEN     | Transaction end                    |
| 105   | TTI_OCCA     | Close all cursors                  |
| 107   | TTI_80SES    | Session operations (Oracle 8)      |
| 115   | TTI_AUTH     | O5LOGON authentication             |
| 118   | TTI_SESS     | Session setup                      |
| 120   | TTI_CANA     | Cancel / close cursor(s)           |
| 125   | TTI_KPN      | Key-pair notification              |
| 135   | TTI_SCID     | Session/connection ID              |
| 138   | TTI_SPFP     | Set protocol feature parameters    |
| 147   | TTI_PING     | Ping                               |

## 4. Authentication Phase

After TNS connection acceptance, the client and server negotiate the TTC protocol, exchange data type capabilities, and perform authentication. The sequence is:

```
Client                              Server
  |                                    |
  |--- TNS_CONNECT ------------------->|
  |<-- TNS_ACCEPT ---------------------|
  |                                    |
  |--- TTI_PRO (protocol negotiation)->|
  |<-- TTI_PRO (server protocol) ------|
  |--- TTI_DTY (data types) ---------> |
  |<-- TTI_DTY (data types) ---------- |
  |--- TTI_FUN/TTI_SESS (session) ---> |
  |<-- TTI_RPA (auth challenge) -------|
  |--- TTI_FUN/TTI_AUTH (auth resp) -->|
  |<-- TTI_RPA (auth result + ver) ----|
  |                                    |
  |        [connected]                 |
```

### 4.1 Protocol Negotiation (TTI_PRO)

Client sends:
```
TTI_PRO | 6 | 5 | 4 | 3 | 2 | 1 | 0 | "python" | 0
```
- `6, 5, 4, 3, 2, 1, 0`: Protocol version vector (descending preference).
- `"python"`: Client driver name (null-terminated).

### 4.2 Data Type Negotiation (TTI_DTY)

Client sends a TTI_DTY message containing:
- Client character set ID (UB2, little-endian).
- Client national character set ID (UB2, little-endian). pyoracle today
  sends the same charset for both; a future revision may differentiate
  the national charset for CJK environments.
- A capability bitmap listing supported Oracle data types and their representations.

### 4.3 Session Setup (TTI_FUN/TTI_SESS)

```
TTI_FUN | TTI_SESS | SeqNum | 1 | UserLen | AuthMode | 1 | NumPairs | 1 | 1 |
  User | KV("AUTH_PROGRAM_NM", app) | KV("AUTH_MACHINE", host) |
  KV("AUTH_PID", pid) | KV("AUTH_SID", user)
```

- **AuthMode**: Bitmask — `1` (basic) | `32` (SYSDBA role) | `128` (PRELIM auth).
- **NumPairs**: Number of key-value pairs (typically 4).

### 4.4 Authentication Challenge (TTI_RPA from Server)

The server responds with TTI_RPA containing key-value pairs:

| Key                    | Description                                    |
|------------------------|------------------------------------------------|
| `AUTH_SESSKEY`         | Server session key (hex-encoded)               |
| `AUTH_VFR_DATA`        | Verifier data / salt (hex-encoded)             |
| `AUTH_PBKDF2_CSK_SALT` | PBKDF2 derived salt (for AES-256 auth)        |

The `AUTH_VFR_DATA` length (NbPair field) determines the authentication variant:

| NbPair | Variant  | Key Size | Cipher      |
|--------|----------|----------|-------------|
| 2361   | O5LOGON  | 128-bit  | AES-128-CBC |
| 6949   | O5LOGON  | 192-bit  | AES-192-CBC |
| 18453  | O5LOGON  | 256-bit  | AES-256-CBC |

### 4.5 Authentication Response (TTI_FUN/TTI_AUTH)

The client computes the authentication response:

**Key derivation** depends on the variant:

- **128-bit (O5LOGON)**: DES-CBC encryption of normalized `USER+PASSWORD`, producing a 16-byte session key.
- **192-bit**: SHA-1 hash of `PASSWORD + unhex(SALT)`, zero-padded to 24 bytes.
- **256-bit**: PBKDF2-HMAC-SHA512 (4096 iterations, 64-byte output) of `PASSWORD` with salt `unhex(AUTH_VFR_DATA) || "AUTH_PBKDF2_SPEEDY_KEY"`, then SHA-512 hashed with the salt.

**Session key exchange**:
1. Decrypt `AUTH_SESSKEY` using the derived key with AES-CBC (IV = 0).
2. Generate a random client session key of the same size.
3. Encrypt the client session key and send it as `AUTH_SESSKEY`.
4. Derive the connection key from XOR/concatenation of server and client session keys, optionally through PBKDF2 for 256-bit variant.

**Password encryption**: The password is PKCS-padded (16-byte blocks with a 16-byte prefix pad) and encrypted with the connection key using AES-CBC (IV = 0).

The auth response message:
```
TTI_FUN | TTI_AUTH | SeqNum | 1 | UserLen | AuthMode | 1 | NumPairs | 1 | 1 |
  User |
  [KV("PROXY_CLIENT_NAME", proxy)]
  KV("AUTH_PASSWORD", encrypted_password) |
  [KV("AUTH_NEWPASSWORD", encrypted_new_password)] |
  [KV("AUTH_PBKDF2_SPEEDY_KEY", encrypted_speedy_key)] |
  KV("AUTH_SESSKEY", encrypted_client_session_key) |
  KV("SESSION_CLIENT_DRIVER_NAME", "python") |
  KV("SESSION_CLIENT_VERSION", "186647296")
```

- **AuthMode**: `256` (O5LOGON) | `1` (password) | `18` (new password) | `32` (SYSDBA) | `128` (PRELIM).

### 4.6 Authentication Result (TTI_RPA from Server)

If successful, the server returns TTI_RPA with:

| Key                   | Description                        |
|-----------------------|------------------------------------|
| `AUTH_SVR_RESPONSE`   | Server proof (hex-encoded)         |
| `AUTH_VERSION_NO`     | Server version number              |
| `AUTH_SESSION_ID`     | Session identifier                 |

The client validates by decrypting `AUTH_SVR_RESPONSE` with the connection key and checking for the presence of `"SERVER_TO_CLIENT"` in the plaintext.

## 5. SQL Execution

### 5.1 Execute (TTI_FUN/TTI_ALL8)

All SQL operations (queries, DML, PL/SQL blocks) use the `TTI_ALL8` function:

```
TTI_FUN | TTI_ALL8 | SeqNum |
  Options(SB4) | Cursor(SB4) |
  QueryPresent(UB1) | QueryLength(SB4) |
  All8Present(UB1) | All8Length(SB4) |
  0 | 0 |
  LongMaxValue(SB4) | FetchRows(SB4) | MaxValue(SB4) |
  BindIndicator(UB1) | [BindCount(SB4)] |
  0 | 0 | 0 | 0 | 0 |
  DefColsPresent(UB1) | DefColsCount(SB4) |
  0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
  [QueryData] | [All8Array] | [OAC descriptors] | [RXD bind data]
```

**Options bitmask**:

| Bit(s)  | Meaning                     |
|---------|-----------------------------|
| 0x0001  | Parse statement             |
| 0x0008  | Bind values present         |
| 0x0010  | Define columns present      |
| 0x0020  | Execute                     |
| 0x0100  | Autocommit                  |
| 0x0400  | PL/SQL block                |
| 0x8000  | Fetch                       |

Common option combinations:
- **SELECT** (new cursor): `0x8021` (parse + execute + fetch), with bind: `0x8029`.
- **SELECT** (reuse cursor): `0x80A0` (execute + fetch + define).
- **DML** (INSERT/UPDATE/DELETE): `0x8021` (+ `0x0100` for autocommit), with bind: `0x8029`.
- **PL/SQL block**: `0x0421` (parse + execute + PL/SQL), with bind: `0x0429`.
- **RETURNING clause**: `0x0421` (same as PL/SQL).
- **Fetch more rows**: `0x8020` or `0x8030` (execute + fetch, with optional define).

**All8 array** encodes execution parameters as SB4 values:
`[Options, FetchCount, 0, 0, 0, 0, 0, Type, 0, 0, 0, 0, 0]`
- Type: `1` for SELECT, `0` for DML/PL/SQL.

**Cursor reuse** *(not yet implemented)*: The protocol supports reusing
a previously-parsed cursor ID instead of resending the SQL text, which
avoids server-side re-parse overhead. pyoracle currently sends
`cursor = 0` on every execute (parse-every-time). A cursor cache is
on the roadmap.

### 5.2 Fetch (TTI_FUN/TTI_FETCH)

For fetching additional rows from an open cursor:

```
TTI_FUN | TTI_FETCH | SeqNum | Cursor(SB4) | RowsToFetch(SB4)
```

The default fetch size is 15 rows (configurable via the `fetch` parameter).

**When a follow-up FETCH is required.** The execute response carries
the OER `call_status` field (`§6.7`). When that value is non-zero it
signals "the server has returned what it can in this packet; more rows
are available on the cursor". The client must then issue a TTI_FETCH
against the open cursor handle to receive the actual row data. This
happens unconditionally when at least one column is a LOB (`§11.9`) —
Oracle returns DCB + RPA piggyback + OER with `call_status = 1` and
no inline rows for LOB queries, regardless of the result-set size.

pyoracle today only consumes whatever rows the server bundles into the
execute response. The follow-up FETCH flow is on the roadmap; without
it, SELECT statements that reference LOB columns or that exceed the
server's inline-row budget return zero rows even though the metadata
parses correctly.

### 5.3 OAC (Oracle Access Column) Descriptor

Each bind variable or column is described by an OAC structure:

```
DataType(UB1) | Flags(3) | Precision(0) | Scale(0) |
MaxDataLength(SB4) | MaxArrayElem(0) | ContFlags(SB4) |
OID(0) | Version(0) | CharsetID(SB4) | CharsetForm(UB1) | MXLC(SB4)
```

**CharsetForm**: `1` for database charset, `2` for national charset (AL16UTF16).

### 5.4 Bind Data (TTI_RXD)

Bind values are encoded inline following OAC descriptors:

| Python Type             | Wire Encoding                                          |
|-------------------------|--------------------------------------------------------|
| `int`, `bool`           | Oracle NUMBER format (length-prefixed mantissa bytes)  |
| `float`, `complex`      | Oracle NUMBER format                                   |
| `decimal.Decimal`       | Oracle NUMBER (integer-valued decimals via int path, fractional via float) |
| `str`                   | Length-prefixed UTF-8 character data (chunked if > 64 bytes) |
| `bytes` / `bytearray`   | Length-prefixed AL16UTF16 character data               |
| `datetime.date`         | 7-byte Oracle DATE (century, year, month, day, h, m, s) |
| `datetime.datetime`     | 7-byte DATE if microsecond == 0; otherwise 11-byte TIMESTAMP (+ 4-byte BE nanoseconds) |
| `datetime.datetime` w/ `tzinfo` | 13-byte TIMESTAMP WITH TIME ZONE (UTC wall clock + offset bias bytes) |
| `None`                  | Single `0x00` byte                                     |
| `oracle.cursor.cursor`  | `0x01, 0x00` (REFCURSOR placeholder)                   |

**Chunked encoding** (for data > 64 bytes): `0xFE` header, then repeated `<length><data>` chunks of up to 64 bytes each, terminated by `0x00`.

## 6. Response Processing

### 6.1 Row Header (TTI_RXH)

Precedes row data in SELECT results. All numeric fields use Oracle's
variable-length integer encoding (`§12.1`), not fixed BE widths:

```
TTI_RXH | Flags(UB1) | NumRequests(UB2) | IterationNumber(UB4) |
NumIters(UB4) | BufferLength(UB2) |
BitVectorLength(UB4) | [SkippedLengthByte(UB1) | BitVector(N bytes)] |
Rxhrid(bytes_with_length)
```

When `BitVectorLength` is non-zero, a single repeated length byte
follows and then `BitVectorLength` raw bytes of bit vector. The
trailing `rxhrid` is a `bytes_with_length` (ub4 count + chunked DALC).

### 6.2 Row Data (TTI_RXD)

Contains the actual column values for one row, encoded according to each column's data type from the describe information.

### 6.3 Bit Vector for Changed Columns (TTI_BVC)

When the server uses differential row encoding it emits a BVC token
between consecutive RXDs. The token body is a `NumColumnsSent` ub2
followed by a packed bit vector. The vector has `ceil(num_columns / 8)`
bytes; bit semantics are LSB-first within each byte (column 0 = bit 0
of byte 0, column 8 = bit 0 of byte 1, etc.).

- **Bit set** → the column is present in the next RXD's data section.
- **Bit unset** → the column value is duplicated from the previous row
  and is *not* carried in the next RXD.

Without honouring the bit vector, the RXD decoder reads too many DALCs
and walks off the end of the packet.

### 6.4 Describe Information (TTI_DCB)

Column metadata for result sets. The 11g layout begins with a header
block that older documents tend to omit:

```
TTI_DCB |
  describe-info preamble (chunked DALC: cursor UUID + Oracle DATE) |
  max_row_size (ub4, skipped) |
  num_columns (ub4) |
  [reserved byte, present only when num_columns > 0] |
  per-column metadata x num_columns (see below) |
  current_date (bytes_with_length, skipped) |
  dcbflag (ub4, skipped) |
  dcbmdbz (ub4, skipped) |
  dcbmnpr (ub4, skipped) |
  dcbmxpr (ub4, skipped) |
  dcbqcky (bytes_with_length, skipped)
```

Per-column metadata on 11g:

```
ora_type_num (ub1) | flags (ub1, skipped) |
precision (sb1) | scale (sb4, variable) |
buffer_size (ub4) | max_array_elems (ub4, skipped) |
cont_flags (ub4, skipped) |
oid (bytes_with_length) |
version (ub2, skipped) | charset_id (ub2) |
csfrm (ub1) | max_size (ub4) |
nulls_allowed (ub1) | v7_name_length (ub1, skipped) |
column_name (str_with_length) |
schema_name (str_with_length, skipped) |
type_name (str_with_length, skipped) |
column_position (ub2, skipped) | uds_flags (ub4, skipped)
```

12c+ uses `sb1` for scale rather than the variable-length sb4 of 11g
and inserts an additional `oaccolid` ub4 after `max_size`. The 11g
layout is what pyoracle currently parses; supporting newer formats
would need a capability-version gate keyed on the negotiated TTC
field version.

### 6.5 I/O Vector (TTI_IOV)

For PL/SQL blocks with OUT parameters, TTI_IOV indicates the direction of each bind variable:
- `16` or `48`: OUT parameter (value returned by the server).
- Other values: IN parameter (value not returned).

### 6.6 Return Parameter (TTI_RPA)

Contains cursor information and bookkeeping after statement execution. For authentication, it carries key-value pairs. For SQL execution, it carries the cursor ID for subsequent fetch operations.

### 6.7 Error Response (TTI_OER)

The OER block is emitted at the end of every server response, success
or failure. The layout is unified — there is no separate "error" vs
"success" structure on the wire; instead every field is always present
and the error code distinguishes the outcome. On 11g:

```
TTI_OER |
  call_status (ub4) |
  end_to_end_seq# (ub2, skipped) |
  current_row_number (ub4)    -- the DML rowcount on 11g (see note) |
  ora_error_code (ub2)        -- 0 on success |
  array_elem_error (ub2, skipped) | array_elem_error (ub2, skipped) |
  cursor_id (ub2) |
  error_position (sb2) |
  sql_type, fatal, flags, user_cursor_options, upi_param,
    warn_flags (6 x ub1) |
  rowid (ub4 rba + ub2 part_id + ub1 + ub4 block_num + ub2 slot) |
  os_error (ub4, skipped) |
  statement_number (ub1, skipped) | call_number (ub1, skipped) |
  padding (ub2, skipped) |
  successful_iterations (ub4)  -- always 1 for non-array execute on 11g |
  oerrdd (bytes_with_length, skipped) |
  num_batch_error_codes (ub2)   [+ batch error codes block]
  num_batch_error_offsets (ub4) [+ batch offsets block]
  num_batch_error_messages (ub2)[+ batch messages block]
  [trailing message DALC iff ora_error_code != 0]
```

**11g rowcount quirk.** The field labelled "current row number" in
newer Oracle (and in python-oracledb's source) doubles as the affected
row count on 11g: an UPDATE / DELETE / INSERT writes the number of
rows touched there. The later `successful_iterations` field is the
call iteration count — always 1 for a single non-array execute — so
it cannot serve as the rowcount the caller wants. 12c+ moved the
affected count to a separate ub8 field at the end of the OER (after
two additional `info.num` / `info.rowcount` extensions); pyoracle
doesn't parse that variant yet.

**Common error codes**:
- `0`: Success.
- `1`: ORA-00001 — unique constraint violated.
- `942`: ORA-00942 — table or view does not exist.
- `1403`: ORA-01403 — no more data (end of result set; normal SELECT
  completion).
- `1722`: ORA-01722 — invalid number.

**Trailing message.** When `ora_error_code != 0`, a single DALC
follows the batch-error-messages count carrying the human-readable
`"ORA-NNNNN: ..."` string. Forward this verbatim to callers — do not
embed a copy of Oracle's error-message catalogue in the driver
(`CONTRIBUTING.md` calls this out explicitly).

### 6.8 Status (TTI_STA)

Indicates successful completion of a transaction operation (COMMIT, ROLLBACK, PING).

### 6.9 Flush Out Binds (TTI_FOB)

Sent by the server when processing RETURNING clauses. The client acknowledges by echoing TTI_FOB back.

## 7. Piggyback Functions (TTI_PFN)

Piggyback functions allow batching cursor management operations with the next request:

```
TTI_PFN | FunctionID | SeqNum | 1 | CursorCount(SB4) | Cursors(SB4[])
```

- **TTI_CANA (120)**: Close specified cursors.
- **TTI_OCCA (105)**: Close all cursors.

These are prepended to the next TTI_FUN/TTI_ALL8 message to avoid extra round trips.

## 8. Transaction Control

Transaction operations are simple TTI_FUN messages:

```
TTI_FUN | FunctionID | SeqNum
```

| Function     | ID  | Description                          |
|-------------|-----|--------------------------------------|
| TTI_COMMIT  | 14  | Commit current transaction           |
| TTI_ROLLBACK| 15  | Rollback current transaction         |
| TTI_COMON   | 12  | Enable autocommit mode               |
| TTI_COMOFF  | 13  | Disable autocommit mode              |
| TTI_PING    | 147 | Connection health check              |

When autocommit is disabled, the library automatically issues a ROLLBACK before closing the connection.

## 9. Database Startup/Shutdown

### Startup (TTI_STRT)

```
TTI_FUN | TTI_SPFP | SeqNum | 1 | 1 | 100 | 1 | 1 | 0 | 0 | 0 | 0 | 0
TTI_FUN | TTI_STRT | SeqNum | Mode(SB4) | 1
```

Modes: `0` = no restrict, `1` = restrict, `16` = force.

### Shutdown (TTI_STOP)

```
TTI_FUN | TTI_STOP | SeqNum | Mode(SB4) | 1
```

Modes: `2` = immediate, `4` = normal, `8` = final, `64` = abort, `128` = transactional.

## 10. Connection Teardown

```
TTI_FUN | TTI_LOGOFF | SeqNum
```

Before closing the socket, the library:
1. Rolls back uncommitted transactions (if autocommit is off).
2. Closes any cached cursors via piggyback TTI_CANA / TTI_OCCA.
3. Sends TTI_LOGOFF and reads its response.
4. **Sends a final empty TNS_DATA packet with `data_flags = 0x0040`**
   (the TNS EOF marker). Without this byte the server can hold the
   session in a half-released state long enough that rapid reconnect
   cycles exhaust the listener and start surfacing ORA-01013 on new
   connections.
5. `shutdown(SHUT_WR)` the socket so the FIN flushes the queued EOF
   packet to the server, then `close()`.

The 10-byte EOF packet wire format is the standard TNS_DATA header
with no body:

```
00 0a | 00 00 | 06 | 00 | 00 40
length | flags | typ| f | data_flags = EOF
```

## 11. Data Type Encoding

### 11.1 Oracle NUMBER

Oracle's proprietary variable-length number format:

- Byte 0: Exponent byte. High bit indicates sign (1 = positive, 0 = negative).
- Bytes 1..N: Mantissa digits, each representing a base-100 digit.
  - Positive: digit + 1 (range 1-100).
  - Negative: 101 - digit (range 1-100), with a trailing `102` sentinel.
- Special value `0x80` represents zero.

### 11.2 Oracle DATE

7-byte fixed format:
```
Century+100 | Year+100 | Month | Day | Hour+1 | Minute+1 | Second+1
```

### 11.3 TIMESTAMP

11 bytes: 7-byte DATE + 4-byte nanosecond fractional seconds (big-endian unsigned integer).

### 11.4 TIMESTAMP WITH TIME ZONE

13 bytes: the 11-byte TIMESTAMP wall clock (which the server expresses
in UTC) plus a 2-byte timezone encoding.

Timezone encoding has two forms:
- **Offset-based**: `Hour + 20`, `Minute + 60` (when bit 0x80 of the
  first byte is clear). pyoracle handles this form.
- **Named zone (region ID)**: when bit 0x80 of the first byte is set,
  the remaining bits encode an Oracle timezone region ID that maps to
  an IANA timezone name via Oracle's built-in zone table. pyoracle
  does not currently ship that table; it surfaces such timestamps as
  naive `datetime.datetime` (no `tzinfo`) rather than guessing.

When decoding, pyoracle treats the wall-clock bytes as UTC and then
shifts to the tagged offset, so the resulting Python `datetime` both
compares equal to the original instant and prints with the original
local time. The encoder is symmetric: a `datetime` with `tzinfo` is
first converted to UTC for the wall-clock bytes, then tagged with the
original offset.

### 11.5 INTERVAL YEAR TO MONTH

5 bytes: `Year(4 bytes, big-endian) | Month(1 byte)`. Both offset by 2147483648 and 60 respectively.

### 11.6 INTERVAL DAY TO SECOND

11 bytes: `Day(4) | Hour(1) | Minute(1) | Second(1) | FracSec(4)`. Day offset by 2147483648; H/M/S offset by 60; FracSec offset by 2147483648.

### 11.7 BINARY_FLOAT / BINARY_DOUBLE

IEEE 754 float/double with sign bit manipulation: negative values are bitwise-inverted; positive values have the sign bit masked off.

### 11.8 ROWID

Encoded as four components: Object ID (UB4), Partition ID (UB2), Block Number (UB4), Slot Number (UB2). Rendered as an 18-character base-64 string (A-Z, a-z, 0-9, +, /) with fixed field widths 6+3+6+3.

### 11.9 LOB Locators (CLOB, NCLOB, BLOB, BFILE)

LOBs are *not* sent inline with row data. What appears in RXD for a
LOB column is a fixed-size **locator** — an opaque server-side handle
(~40 bytes) plus a couple of metadata fields. Reading the actual LOB
content requires a separate `TTI_LOBOPS` round-trip per locator
(`§14`).

The per-column wire layout in RXD for a LOB:

```
ub4    num_bytes           # 0 = NULL LOB; otherwise size of locator block
[
  ub8    size                # in bytes (CLOB/NCLOB: characters)
  ub4    chunk_size          # server-preferred read chunk size
  DALC   locator             # opaque locator bytes
]                            # CLOB / NCLOB / BLOB

[ DALC   locator ]           # BFILE (no size / chunk_size prefix)
```

Per python-oracledb the locator buffer is canonically 40 bytes;
internal flags inside the locator (`TNS_LOB_LOC_OFFSET_FLAG_*`)
distinguish temporary LOBs that need cleanup on close from regular
ones. Embedding the locator format isn't necessary on the client
side — the bytes are opaque to anything other than `TTI_LOBOPS`.

The TNS data type numbers (`§3.1`) for LOBs are:

| Type    | TNS code |
|---------|----------|
| CLOB    | 112      |
| BLOB    | 113      |
| BFILE   | 114      |
| NCLOB   | 112 + national charset form |

pyoracle does not currently parse the locator structure or issue the
`TTI_LOBOPS` round-trip; LOB columns will fail to decode under the
current row reader, and SELECT statements that reference LOB columns
hit the no-rows-inline path described in `§5.2` regardless.

## 12. Wire Encoding Primitives

### 12.1 Variable-Length Integer (SB4/SB2)

A compact encoding for 32-bit integers:

| Value         | Encoding                         |
|---------------|----------------------------------|
| 0             | `0x00`                           |
| 0..255        | `0x01, <byte>`                   |
| 0..65535      | `0x02, <hi>, <lo>`               |
| 0..16777215   | `0x03, <b2>, <b1>, <b0>`        |
| 0..4294967295 | `0x04, <b3>, <b2>, <b1>, <b0>`  |
| Negative      | `0x80|flag, <magnitude>`         |

### 12.2 DALC (Data with Attached Length Code)

Variable-length data with a length prefix:

| Length     | Encoding                                                     |
|------------|--------------------------------------------------------------|
| 0 (empty)  | `0x00`                                                       |
| 1..253     | `<length>, <data>`                                           |
| 254 (long) | `0xFE`, then chunked: repeated `<chunk_len>, <chunk_data>` (max 64 bytes per chunk), terminated by `0x00` |
| 255 (null) | `0xFF` — null marker, no data follows                        |

### 12.3 Key-Value Pair Encoding

Used in authentication messages:

```
KeyLength(SB4) | KeyLen(UB1) | KeyData | ValueLength(SB4) | ValueLen(UB1) | ValueData | NbPair(SB4)
```

Zero-length keys or values are encoded as a single `0x00` byte.

## 13. Character Set Support

The library supports a wide range of Oracle character sets, identified by Oracle character set IDs:

| Charset          | ID    | Charset          | ID    |
|------------------|-------|------------------|-------|
| US7ASCII         | 1     | AL32UTF8         | 873   |
| WE8ISO8859P1     | 31    | AL16UTF16        | 2000  |
| EE8ISO8859P2     | 32    | JA16EUC          | 830   |
| WE8MSWIN1252     | 178   | JA16SJIS         | 832   |
| CL8MSWIN1251     | 171   | ZHS16GBK         | 852   |
| UTF8             | 871   | ZHT16BIG5        | 865   |

The default character set is AL32UTF8 (873). For CJK and AL16UTF16 character sets, the national character set is set to UTF-8 for proper conversion.

## 14. LOB Operations (TTI_LOBOPS)

LOB content is transferred via the `TTI_LOBOPS` function call
(`TTI_FUN | TTI_LOBOPS | …`). The same function multiplexes a family
of opcodes — read, write, get length, trim, get chunk size, create
temporary LOB, free temporary LOB, open, close, plus BFILE-specific
operations. The wire layout is the same for all of them; the opcode
field selects behaviour.

### 14.1 Common request layout

```
TTI_FUN | TTI_LOBOPS | SeqNum |
  ub1 source_pointer_flag    # 1 if source locator is sent, else 0
  ub4 source_locator_length  # bytes following at the locator slot
  ub1 dest_pointer_flag      # 0 for plain reads
  ub4 dest_length            # read amount target (bytes/chars)
  ub4 short_source_offset    # 0; long offset goes below
  ub4 short_dest_offset      # 0
  ub1 charset_pointer_flag   # 0 except for CREATE_TEMP
  ub1 short_amount_flag      # 0; long amount goes below
  ub1 null_lob_pointer_flag  # 1 for CREATE_TEMP / IS_OPEN / FILE_*
  ub4 operation              # opcode, see below
  ub1 scn_array_pointer_flag # 0
  ub1 scn_array_length       # 0
  ub8 source_offset          # 1-based offset into the LOB
  ub8 dest_offset            # 0 for plain reads
  ub1 amount_pointer_flag    # 1 if amount is sent at end
  ub16be 0, 0, 0             # three reserved array-LOB slots
  [ raw  locator ]           # raw bytes, length = source_locator_length
  [ ub8  amount ]            # if amount_pointer_flag == 1
```

### 14.2 Opcodes

| Value     | Name              | Description                          |
|-----------|-------------------|--------------------------------------|
| `0x0001`  | GET_LENGTH        | Total length of the LOB              |
| `0x0002`  | READ              | Read content from the LOB            |
| `0x0020`  | TRIM              | Truncate the LOB                     |
| `0x0040`  | WRITE             | Write content into the LOB           |
| `0x0100`  | FILE_OPEN         | Open a BFILE                         |
| `0x0200`  | FILE_CLOSE        | Close a BFILE                        |
| `0x0400`  | FILE_ISOPEN       | Test whether a BFILE is open         |
| `0x0800`  | FILE_EXISTS       | Test whether a BFILE exists          |
| `0x4000`  | GET_CHUNK_SIZE    | Server-preferred chunk size          |
| `0x0110`  | CREATE_TEMP       | Allocate a temporary LOB             |
| `0x0111`  | FREE_TEMP         | Release a temporary LOB              |
| `0x8000`  | OPEN              | Open the LOB                         |
| `0x10000` | CLOSE             | Close the LOB                        |
| `0x11000` | IS_OPEN           | Test whether the LOB is open         |
| `0x80000` | ARRAY             | Array-style operation                |

### 14.3 Response

The server returns a `TNS_MSG_TYPE_LOB_DATA` (= 14) message carrying
the LOB chunk as length-prefixed bytes:

```
0x0E  msg_type = LOB_DATA
DALC  data            # raw bytes for BLOB/BFILE;
                      # decode as per-LOB charset for CLOB/NCLOB
```

For `GET_LENGTH` / `READ` / similar value-returning opcodes, the
server then emits the standard `TTI_RPA` return-parameters block
followed by the OER status. The `RPA` return block echoes the
updated locator (the server may rewrite internal flags) and, for
operations declared with `send_amount`, an `sb8` carrying the actual
amount read/written. `IS_OPEN`, `FILE_EXISTS`, `FILE_ISOPEN` add a
trailing `ub1` boolean flag.

### 14.4 Status (not implemented)

pyoracle does not currently issue `TTI_LOBOPS` requests or handle the
`TNS_MSG_TYPE_LOB_DATA` response. Implementing this is the second
half of LOB support; the first half is the call-status-driven FETCH
flow described in `§5.2`.

## 15. TNS Marker Protocol

TNS_MARKER packets serve as break/attention signals. The marker body is 3 bytes:

- `0x01, 0x00, 0x02`: Standard marker. Client responds with the same marker pattern.
- `0x01, 0x00, 0x01`: Break marker. Triggers a read-timeout mode where the client reads with a short timeout to collect remaining data.

## 16. Sequence Numbers

Each TTC function call includes an incrementing sequence number (1 byte, wrapping from 127 back to 1). The sequence number is managed per-connection and ensures ordered request processing.
