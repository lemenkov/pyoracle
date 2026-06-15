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

- **Data Flags** (16 bits): on the **client -> server** side, `0x0000` for a
  final (or only) packet and `0x0020` when more data packets follow. The
  **server -> client** side does *not* use this bit: every server data packet,
  final or not, carries Data Flags `0x0000` (verified by probe against XE 11g —
  26 consecutive fragments of a 50 KiB CLOB read were all `0x0000`). The server
  instead signals "more fragments follow" by **filling the packet to its
  maximum size** (see §1.3). Do not rely on `0x0020` to delimit an inbound
  message.

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

**Client -> server** (requests we send):

- All fragments except the last have Data Flags set to `0x0020`.
- The last fragment has Data Flags set to `0x0000`.

**Server -> client** (responses we receive):

- The server does **not** flag fragments at all — Data Flags are `0x0000` on
  every packet (see §1.1).
- Continuation is signalled by **packet size**: a non-final fragment is filled
  to the server's maximum packet size (observed as `SDU - 37` = 8155 bytes for
  the default 8192 SDU; a second framing yields `SDU - 81`). A packet smaller
  than that maximum is the final fragment.
- The receiver reassembles by concatenating fragment bodies until it sees a
  short (sub-maximum) packet. `assemble_packet()` / `recv()` in
  `oracle/connection.py` implement exactly this size test.

In principle the size test cannot distinguish a final fragment that happens to
be *exactly* maximum-sized from a true continuation. In practice this has not
been observed as the cause of any desync (the server appears to avoid emitting
a maximally-sized final fragment), so the test holds for normal traffic.

### 1.4 Break / attention markers (TNS_MARKER)

A `TNS_MARKER` (type 12) is an out-of-band break/attention signal. The server
emits one (often several in a row — a "marker storm") to **cancel the call in
progress**, e.g. when XE's per-second new-connection throttle rejects a logon
with `ORA-01013` ("user requested cancel of current operation").

Semantics that matter for the receive path:

- A marker **cancels in-flight data**: any bytes the server had already queued
  before the break are stale and must be **discarded**, not reassembled. The
  real response (the `ORA-01013` OER, etc.) arrives *after* the marker exchange.
- `recv()` therefore returns a marker immediately and drops whatever else was
  buffered in the same read; the caller (`_handle_response` / `_read_lob_response`)
  replies with a reset marker (`\x01\x00\x02`) and reads again for the real
  response. **Do not** "preserve" the post-marker bytes — that re-injects the
  cancelled data and desyncs the stream (verified: doing so reds ~65 integration
  tests on 11g).
- pyoracle never *initiates* a break, so the client-side interrupt/reset
  discard handshake does not arise here.

> ⚠️ **Open: #45 desync.** Under full-suite load / connection churn a LOB read
> can still occasionally land content in the wrong column (a CLOB read returns
> empty and its bytes surface in the next BLOB column). The rapid-reconnect
> reproduction instead trips XE's `ORA-01013` connection throttle (a marker
> storm), and a *paced* standalone reproduction of the exact failing query is
> clean over 490+ rounds — so the wrong-column desync has **not** yet been
> isolated to a specific code path. Per the project's capture-first discipline,
> the next step is a wire capture of a failing sequence (marker handling around
> a LOB read is the prime suspect) before changing the framing code. Blocks safe
> connection reuse and reliable 21c CI.

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

The server may redirect the client to a different address — common with
shared-server (the listener hands off to a dispatcher), RAC, and listeners
that register services dynamically. The redirect body (everything after the
8-byte header, often after a 2-byte data-length) is an ASCII connect
descriptor carrying the new address, e.g.
`(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=...)(PORT=...))...)`. It may also
echo the original `CONNECT_DATA` (whose `CID` holds the *client* host) after a
NUL, so the parser scopes to the `ADDRESS` block for the reconnect target.

pyoracle follows the redirect: it pulls `HOST`/`PORT` out of the `ADDRESS`,
closes the socket, reconnects to that address, and re-sends `TNS_CONNECT` to
restart the handshake there. Redirects are capped (5) so a looping listener
fails fast rather than spinning. Sync and async (`§handle_login`).

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

The server replies with a TTI_PRO message carrying its own capabilities — this
is where the client learns the server's TTC field version and negotiates the
effective one (`min(client, server)`). Layout (`decode_token_pro`):
```
TTI_PRO | server_version (UB1) | 0 |
  banner (NUL-terminated) | charset_id (UB2 LE) | server_flags (UB1) |
  num_elem (UB2 LE) | num_elem × 5 bytes (charset element array) |
  fdo_length (UB2 BE) | fdo[fdo_length] |
  compile_caps (UB1 len + bytes) | runtime_caps (UB1 len + bytes)
```
The server's field version is `compile_caps[7]` (`CCAP_FIELD_VERSION`, §4.2).
pyoracle stores the negotiated minimum as `connection.field_version` and sends
it back in its own DTY; against 11g both sides are `6` (11.2). `server_version`
is the TTC protocol byte (`6` = 8.1+), distinct from the product release that
arrives later in the auth result (`AUTH_VERSION_NO`).

### 4.2 Data Type Negotiation (TTI_DTY)

TTI_DTY (message type `2`, `TNS_MSG_TYPE_DATA_TYPES`) advertises the client's
capabilities and the wire representation it wants for each Oracle data type:

```
msgtype=2 | charset_in (UB2 LE) | charset_out (UB2 LE) | flag (UB1) |
  ccap_len (UB1) | compile_caps[ccap_len] |
  rcap_len  (UB1) | runtime_caps[rcap_len] |
  datatype table | 0
```

- **charset_in / charset_out**: NLS (database) and national charset ids.
  pyoracle advertises **AL32UTF8 (873)** for both. This must be 873 (real
  UTF-8), **not** Oracle's legacy "UTF8" (871) — 871 is CESU-8, which encodes
  supplementary-plane characters (emoji, rare CJK, U+10000 and above) as a
  six-byte surrogate pair instead of a four-byte sequence, and Python's `utf-8`
  codec then decodes them to replacement characters. Advertising 873 for
  `charset_out` makes the server convert national (AL16UTF16) `NCHAR` /
  `NVARCHAR` / `NCLOB` data to AL32UTF8 on the wire — lossless, since both
  cover all of Unicode — so the same UTF-8 decode path handles national columns
  without a separate AL16UTF16 step. (#29)
- **compile_caps / runtime_caps**: two length-prefixed byte arrays. Each index
  is a named feature slot (`TNS_CCAP_*` / `TNS_RCAP_*`). The most important is
  the **field version** at compile-cap index 7 (`TNS_CCAP_FIELD_VERSION`): it
  selects the auth-verifier scheme and the version-gated wire formats the rest
  of the session uses. pyoracle advertises `16` (21.1) by default and the
  server negotiates it down to its own max (`min(client, server)`), so an 11g
  server settles on `6` (11.2) and pyoracle then emits the 11g vectors/formats;
  pass `field_version=FIELD_VERSION_11_2` to force the legacy vector. The
  capability *contents* are stable across 12c+ releases, so for any negotiated
  12c+ version pyoracle renders the 21.1 base vector with that version byte
  patched in (`capability_arrays`).
- **datatype table**: per-type `(type, conv, repr, flags)` entries. pyoracle
  uses the 11g 1-byte-per-field form (4 bytes/entry, terminated by `0 0`); 12c+
  uses a 2-byte-per-field form (`UB2`×4, terminated by `UB2 0`).

Selected capability indices (reverse-engineered from python-oracledb's
`constants.pxi`/`data_types.pyx` and verified against live 11g and 21c
captures), with the values pyoracle's 11.2 vector vs python-oracledb's 21.1
vector send:

| idx | name | 11.2 | 21.1 | notes |
|----:|------|-----:|-----:|-------|
| 0 | SQL_VERSION | 6 | 6 | `SQL_VERSION_MAX` |
| 4 | LOGON_TYPES | 0x6a | 0xea | 21.1 adds `O8LOGON_LONG_IDENTIFIER` |
| 5 | FEATURE_BACKPORT | 1 | 0x18 | |
| 7 | **FIELD_VERSION** | **6** | **16** | the version gate |
| 23 | LOB | 0x4f | 0xcf | 21.1 adds `LOB_12C` |
| 27 | UB2_DTY | 0 | 1 | 2-byte data-type ids |
| 34 | CLIENT_FN | 6 | 12 | `CLIENT_FN_MAX` |
| 37 | TTC3 | 1 | 0xb8 | |
| 39 | SESS_SIGNATURE_VERSION | — | 8 | new 12c+ slot |
| 52 | VECTOR_FEATURES | — | 3 | new (23ai vectors) |

The compile array grew from 38 bytes (`TNS_CCAP_MAX` 11g) to 53 (12c+); the
runtime array from 7 to 11, with runtime index 6 (`TNS_RCAP_TTC`) gaining
`ZERO_COPY | 32K` (`0x05`). pyoracle models both arrays as `{index: value}`
maps keyed on the field version in `oracle/tns.py` (`capability_arrays`).

> **12c+ blocker (issue #27).** Advertising a 12c+ field version is necessary
> for 21c login but not sufficient: it changes how the server frames every
> subsequent message (DTY table form, OER layout, datatype encodings), so it
> must land together with the matching version-gated decoders. The 256-bit
> O5LOGON crypto is already solved (§4.5); the capability layout is now fully
> mapped (this section); the remaining work is the version-gated formats.

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
- **192-bit** (11g XE): SHA-1 hash of `PASSWORD + unhex(SALT)`, zero-padded to 24 bytes (the
  AES-192 `KeySess`).
- **256-bit** (12c+, e.g. 21c XE): `Data = PBKDF2-HMAC-SHA512(PASSWORD, salt =
  unhex(AUTH_VFR_DATA) || "AUTH_PBKDF2_SPEEDY_KEY", iterations = AUTH_PBKDF2_VGEN_COUNT
  (4096), dklen = 64)`, then `KeySess = SHA-512(Data || unhex(AUTH_VFR_DATA))[:32]` (the
  AES-256 key). `Data` is also carried to the server in `AUTH_PBKDF2_SPEEDY_KEY` (below).

**Session key exchange**:
1. Decrypt `AUTH_SESSKEY` (server's) with `KeySess` using AES-CBC (IV = 0) → `SrvSess`.
2. Generate a random client session key `CliSess` of the same size.
3. Encrypt `CliSess` with `KeySess` and send it as `AUTH_SESSKEY`.
4. Derive the connection key `ConnKey` from the server and client session keys:
   - 128-bit: MD5 over XOR/concatenation; 192-bit: MD5-based, 24 bytes.
   - **256-bit**: `ConnKey = PBKDF2-HMAC-SHA512(hexlify(CliSess || SrvSess), salt =
     unhex(AUTH_PBKDF2_CSK_SALT), iterations = AUTH_PBKDF2_SDER_COUNT (3), dklen = 32)`.
     Note the order — **client session key first**, and the *unpadded* keys are concatenated.

**Password encryption**: `AUTH_PASSWORD = AES-CBC(ConnKey, IV=0)` of `pad1(PASSWORD)`, where
`pad1` is a 16-byte prefix block + `PASSWORD` + PKCS#7 padding. Sent hex-encoded (uppercase).

**256-bit field encoding (verified against python-oracledb / 21c on the wire):**
- `AUTH_SESSKEY` (client, 32 bytes), `AUTH_PASSWORD` (32 bytes) and `AUTH_PBKDF2_SPEEDY_KEY`
  (80 bytes) are encrypted block-aligned and sent **as-is, NOT given an extra PKCS#7 block**
  (the client session key is the raw 32-byte `CliSess`; the speedy key is `random(16) ||
  Data(64)`). All three values are **hex-encoded** (uppercase) on the wire — sending the
  speedy key as raw bytes gives `ORA-03146` ("invalid buffer length for TTC field").
- `AUTH_PBKDF2_SPEEDY_KEY` carries `Data` so the server can recover it (and verify the
  password) without the plaintext.

> **12c+ login status (UNSOLVED):** the 256-bit crypto above is implemented and verified
> byte-identical to python-oracledb — every derived value matches and the `TTI_AUTH` message
> is byte-structurally identical to oracledb's (same logon mode, key/value set, KV flags, and
> field encodings). Yet 21c still returns `ORA-01017`. The remaining difference is **not** in
> the auth message; the leading suspect is the capability negotiation (oracledb's DTY exchange
> is far larger than pyoracle's), which may gate the server's acceptance of the 12c verifier.
> Still under investigation.

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

`AUTH_VERSION_NO` is a decimal string of a single packed integer holding
the server's release. Decode it as `major` (bits 24-31), `minor`
(20-23), `update` (12-19), `patch` (8-11), `port-specific update`
(0-7) — e.g. `186647040` = `0x0B200200` = `11.2.0.2.0`, matching
`product_component_version` on XE. pyoracle exposes the dotted form as
`Connection.version` and masks the major release out for its protocol
version gate.

### 4.7 Password Change (TTI_FUN/TTI_AUTH on a live session)

`Connection.changepassword(old, new)` (#21) reuses the **already-authenticated
session** rather than re-running the handshake. After a normal login it sends a
single `TTI_AUTH` (0x73) call whose layout is identical to the login OAUTH
(§4.5) except:

- **Logon mode `0x102`** = `WITH_PASSWORD` (0x100) | `CHANGE_PASSWORD` (0x02),
  and notably *without* the `LOGON` (0x01) bit the login carries.
- Exactly **two** key/value pairs and **no** `AUTH_SESSKEY` /
  `AUTH_PBKDF2_SPEEDY_KEY` — the session key from login is reused:

  | Key                | Value                                              |
  |--------------------|----------------------------------------------------|
  | `AUTH_PASSWORD`    | current password, AES-CBC(IV=0) under the ConnKey  |
  | `AUTH_NEWPASSWORD` | new password, encrypted the same way               |

Both values use the same encryption as the login `AUTH_PASSWORD`
(`encrypt_password`): a fixed 16-byte block is prepended (the server discards
it) so the first ciphertext block is shared — a fresh random prefix, as
oracledb sends, is not required. Wire layout (mirrors `encode_dictionary_auth`):

```
TTI_FUN | TTI_AUTH | SeqNum | 1 | UserLen(SB4) | LogonMode=0x102(SB4) |
  1 | KVCount=2(SB4) | 1 | 1 | UserField |
  KV(AUTH_PASSWORD) | KV(AUTH_NEWPASSWORD)
```

The server replies with a `TTI_RPA` + `TTI_OER`: error code 0 on success (the
session stays usable), `ORA-28008` for a wrong current password, or e.g.
`ORA-28003` when a password-verify function rejects the new one. Verified on
both 11g (128/192-bit O5LOGON) and 21c (256-bit). Reverse-engineered from an
oracledb-thin capture through the logging proxy (`tools/capture_proxy.py`).

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

**Cursor reuse**: The protocol allows reusing a previously-parsed cursor ID
instead of resending the SQL text, skipping the server-side re-parse. pyoracle
caches the cursor id the server returns (per connection, LRU, DML only) and on
a repeat execute of the same SQL sends that id with an empty query string; the
OAC descriptors are then omitted (the server already knows the column types
from the first parse) and only the `TTI_RXD` bind values are sent.

**Anonymous PL/SQL blocks** (`BEGIN`/`DECLARE` …) must use the PL/SQL option
set (`0x0421` / `0x0429`), not the DML `change` set — sending a block with
binds through the DML path is rejected with `ORA-00600 [12259]`. The returned
OUT/IN OUT values come back in a `TTI_IOV` token (§6.5).

**Array DML batch errors and row counts** (`executemany`, 12c+). Two optional
modes layer onto an array-DML execute, each oracledb-compatible:

- **`batcherrors`** — OR `0x80000` (`TNS_EXEC_OPTION_BATCH_ERRORS`) into the
  leading Options word. A per-row error then no longer aborts the batch; the
  good rows apply and the failures come back in the OER's batch-error
  code/offset/message arrays (§6.7), summarised by a non-fatal `ORA-24381`.

- **`arraydmlrowcounts`** — ask the server for the per-iteration affected-row
  count. Two coordinated request-side changes (no Options bit):
  1. `al8i4[9]` (the 10th All8 element, normally `0`) is set to `0xC000`.
  2. The 12c+ `al8pidmlrc` block — the three zero bytes that follow the
     register-id field in the post-11g OALL8 header — becomes
     `01 | iteration_count(SB4) | 01` (e.g. four iterations → `01 01 04 01`).

  Omitting either makes the server reject the execute as malformed
  (`ORA-03137 [kpoal8Check-4]`). The counts come back in the response **RPA
  region** (`TTI_RPA`, token 8) that precedes the trailing OER, as a
  `count(UB4) | count × UB4` block sitting between the opaque RPA body and the
  OER token. pyoracle extracts it in `decode_token_rpa_piggyback` (armed for
  the execute via a context flag) and surfaces it through
  `cursor.getarraydmlrowcounts()`. The two modes combine: a failed iteration
  reports a row count of `0`.

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

pyoracle implements the FETCH flow in `OracleConnect._drain_cursor`:
after the initial EXEC response, if `call_status == 1` and a cursor
handle was returned, it loops issuing `TTI_FETCH` (with the prior
DCB's RowFormat threaded into the decoder via `_handle_response`'s
`Acc` parameter, since FETCH responses don't repeat the DCB) until
the server returns `ORA-01403` end-of-fetch. Rows are concatenated
across responses and surfaced as one result set; the 1403 sentinel
is masked to 0 so it doesn't reach the caller as an error. Works for
any large non-LOB SELECT; LOB column data still needs a per-column
row decoder (`§11.9`).

### 5.3 OAC (Oracle Access Column) Descriptor

Each bind variable or column is described by an OAC structure:

```
DataType(UB1) | Flags(3) | Precision(0) | Scale(0) |
MaxDataLength(SB4) | MaxArrayElem(0) | ContFlags(SB4) |
OID(0) | Version(0) | CharsetID(SB4) | CharsetForm(UB1) | MXLC(SB4)
```

**CharsetForm**: `1` for database charset, `2` for national charset (AL16UTF16).

The layout above is the 11g form. 12c+ (field version >= 12.2,
`encode_token_raw`) uses oracledb's `_write_column_metadata` layout instead:
a fixed flag byte (`TNS_BIND_USE_INDICATORS = 1`), `ContFlags` as a `ub8`, an
`OID`/`Version`, the bind charset as a `ub2` (AL32UTF8 = 873 for char binds,
0 otherwise), the `CharsetForm` byte, a LOB-prefetch length, and a trailing
`oaccolid` `ub4`. Sending the 11g OAC to a 12c server is rejected with
`ORA-03115` (unsupported network datatype). The bind *value* (TTI_RXD) is the
same in both, except long values use the version-gated `bytes_with_length`
chunking described in §6.4 (`encode_chr`): 11g chunks anything over 64 bytes
with single-byte lengths, 12c+ sends a single length below 254 and `ub4`
chunks above it (sending the 11g chunking to 12c gives `ORA-03120`).

**MaxDataLength and the LONG-reorder trap**: `MaxDataLength` must reflect the
value's real size, **not** a flat maximum. A VARCHAR/RAW bind whose
`MaxDataLength` exceeds the 4000-byte VARCHAR2 limit is treated by the server
as a streamed LONG and processed *after* the following bind — which silently
reorders binds relative to their placeholders (so e.g. `SET name=:1 WHERE
id=:2` binds the string to `id`). pyoracle therefore sizes a VARCHAR/RAW OAC to
the actual value's byte length (NULL → 1); values genuinely over 4000 bytes
keep their true size and the intended LONG handling (the multi-KiB CLOB/BLOB
regular-path bind). For array DML the single OAC is sized to the widest value
in each column across all rows.

### 5.4 Bind Data (TTI_RXD)

Bind values are encoded inline following OAC descriptors:

| Python Type             | Wire Encoding                                          |
|-------------------------|--------------------------------------------------------|
| `int`, `bool`           | Oracle NUMBER format (length-prefixed mantissa bytes)  |
| `float`, `complex`      | Oracle NUMBER format (non-finite `inf`/`nan` auto-route to BINARY_DOUBLE) |
| `decimal.Decimal`       | Oracle NUMBER (integer-valued decimals via int path, fractional via float) |
| `oracle.BinaryFloat`    | 4-byte order-preserving IEEE-754 (§11.7)               |
| `oracle.BinaryDouble`   | 8-byte order-preserving IEEE-754 (§11.7)               |
| `str`                   | Length-prefixed UTF-8 character data (chunked if > 64 bytes) |
| `bytes` / `bytearray`   | Length-prefixed RAW (verbatim bytes)                   |
| `datetime.date`         | 7-byte Oracle DATE (century, year, month, day, h, m, s) |
| `datetime.datetime`     | 7-byte DATE if microsecond == 0; otherwise 11-byte TIMESTAMP (+ 4-byte BE nanoseconds) |
| `datetime.datetime` w/ `tzinfo` | 13-byte TIMESTAMP WITH TIME ZONE (UTC wall clock + offset bias bytes) |
| `datetime.timedelta`    | 11-byte INTERVAL DAY TO SECOND (§11.6)                 |
| `oracle.IntervalYM`     | 5-byte INTERVAL YEAR TO MONTH (§11.5)                  |
| `None`                  | Single `0x00` byte                                     |
| `oracle.Var` (OUT/IN OUT) | the seeded value, or `0x00` (NULL) for a pure OUT; OAC driven by the Var's declared type |
| `oracle.cursor.cursor` / `Var(oracle.CURSOR)` | `0x01, 0x00` (REF CURSOR placeholder); value returned in the IOV (§6.5) |

**Chunked encoding** (for data > 64 bytes): `0xFE` header, then repeated `<length><data>` chunks of up to 64 bytes each, terminated by `0x00`.

**Array DML** (`executemany`): the OAC descriptors are sent once (sized to the
widest value in each column across all rows), the All8 iteration count is the
number of rows, and each row's values follow as its own `TTI_RXD` token after
the OAC block.

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

12c+ (field version >= 12.2) differs from 11g in the per-column block:
scale is `sb1` (a raw signed byte) rather than 11g's variable-length
sb4, and an extra `oaccolid` ub4 follows `max_size`. pyoracle decodes
both, gated on the negotiated TTC field version (§4.2): the response
handler passes `connection.field_version` into `decode_packet`, which
publishes it (via a `ContextVar`) to the token decoders for the duration
of that response.

**23ai (field version 17)** appends two more per-column fields after
`uds_flags`: the column's **SQL-domain schema** and **domain name**, each a
`str_with_length` (a `ub4` count, then a DALC string — the same codec as
`column_name`), empty (a single `00`) for a column with no domain. Earlier
pyoracle read them as plain `ub4`s, which only survives the empty case; a real
domain (`01 03 03 'PYO' 01 07 07 'PYO_DOM'`) then desynced the row decode
(#53). Reverse-engineered by diffing a domain column vs a plain one on 23ai and
cross-checked against python-oracledb's `domain_schema` / `domain_name`. Column
**annotations** are carried elsewhere in the describe (a plain column and an
annotated one have identical trailing fields here), so they neither surface nor
desync at this point — surfacing them is future work.

**Chunked (LONG) values.** A value whose length byte is `254` is sent in
chunks. On 11g each chunk is a single length byte followed by that many
data bytes, terminated by a zero byte. 12c+ prefixes each chunk with a
`ub4` length and ends with a zero-length chunk (the same framing as every
other `bytes_with_length` field). `decode_chr` picks the form by field
version; without this a multi-chunk value (e.g. a 300-char string) walks
off the end of the buffer. The same single-byte-vs-`ub4` chunk-length
split applies to LONG / LONG RAW columns (`_read_long_column`, which on
12c+ also sends the chunk after a `0xFE` marker with `ub4` lengths).

### 6.5 I/O Vector (TTI_IOV)

When an executed anonymous PL/SQL block carries bind variables, the server
replies with a `TTI_IOV` token that lists each bind's direction and is
immediately followed (when any bind is OUT / IN OUT) by the returned values.
Layout reverse-engineered from XE 11g and cross-referenced with
python-oracledb's `_process_io_vector`:

```
ub1   token (TTI_IOV = 11)
ub1   flag                                   (skip)
ub2   num_requests   \  num_binds =
ub4   num_iters      /    num_iters * 256 + num_requests
ub4   num iters this time                    (skip)
ub2   uac buffer length                      (skip)
ub2   fast-fetch bit-vector length + bytes   (skip)
ub2   rowid length + bytes                   (skip)
per bind:
  ub1 direction                              # 16 OUT, 32 IN, 48 IN OUT
```

**Direction codes** (`TNS_BIND_DIR_*`): `16` = OUT, `32` = IN, `48` = IN OUT.

If any bind is OUT / IN OUT, a `TTI_RXD` (`0x07`) token follows, then one
value per OUT / IN OUT bind **in bind order** (IN binds contribute nothing):

- **Scalar** OUT value: a DALC blob (decoded by the bind's declared type) plus
  a trailing 1-byte indicator (`0x00` = present).
  e.g. NUMBER `10` → `02 c1 0b 00`, VARCHAR `"hi!"` → `03 68 69 21 00`.
- **REF CURSOR** OUT value: a 1-byte length, then an inline describe of the
  cursor's result set (the same per-column metadata as a `TTI_DCB`, §6.4),
  then the nested cursor id (`ub2`) and a 1-byte indicator. The client then
  drains that cursor id with `TTI_FETCH` (§5.2). See python-oracledb's
  `_create_cursor_from_describe`.

After the values come the usual `TTI_RPA` and `TTI_OER` tokens.

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
  rowid (ub4 data_object + ub2 rel_file + ub1 + ub4 block + ub2 slot) |
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

**Rowid → `lastrowid`.** The `rowid` field carries the rowid of the row
the statement touched, in the same physical-rowid layout as a ROWID
column (`§14`): data object number, relative file number, an unused
byte, block number, slot number. pyoracle renders it via the same
base-64 encoder and surfaces it as `Cursor.lastrowid` for
INSERT / UPDATE / DELETE. For a SELECT the server fills it with the last
fetched row's rowid, which is not a "last modified row", so the driver
clears `lastrowid` on result-set statements; a zero block number (DDL /
no row) means no rowid.

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

On 11g that DALC comes right after the batch-error arrays. 12c+ inserts
the extended-precision error number (`ub4`) and rowcount (`ub8`) before
it, and 20.1+ adds a `ub4` SQL type and `ub4` server checksum. `decode_
token_oer` skips these by field version (§4.2); without it the message
DALC is mis-aligned and decodes to garbage even though the early
`ora_error_code` (and thus the exception class) is still correct.

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
  the two TZ bytes carry an Oracle timezone region id instead of an
  offset: `region_id = ((byte0 & 0x7f) << 6) + (byte1 >> 2)`. pyoracle
  maps the id to an IANA zone name (`oracle/_tzregions.py`, a stable
  id→name table generated from the server's `V$TIMEZONE_NAMES`) and then
  asks the standard-library `zoneinfo` module for the offset **at that
  instant** — so DST is applied correctly and offsets track the live IANA
  tz database rather than any table frozen into an Oracle release. An id
  not present in the table (a few obsolete Oracle aliases) falls back to a
  naive `datetime.datetime`.

When decoding, pyoracle treats the wall-clock bytes as UTC and then
shifts to the tagged offset, so the resulting Python `datetime` both
compares equal to the original instant and prints with the original
local time. The encoder is symmetric: a `datetime` with `tzinfo` is
first converted to UTC for the wall-clock bytes, then tagged with the
original offset.

### 11.5 INTERVAL YEAR TO MONTH

5 bytes: `Year(4 bytes, big-endian) | Month(1 byte)`, biased by `2**31` and `60`
respectively. Both fields share the interval's sign. Maps to
`oracle.IntervalYM(years, months)`.
Example: `3-7` → `80 00 00 03 43` (years `0x80000003 − 2**31 = 3`, months
`0x43 − 60 = 7`); `-1-2` → `7f ff ff ff 3a`.

### 11.6 INTERVAL DAY TO SECOND

11 bytes: `Day(4) | Hour(1) | Minute(1) | Second(1) | FracSec(4, BE
nanoseconds)`. Day biased by `2**31`; H/M/S biased by `60`; FracSec biased by
`2**31`. All fields share the interval's sign. Maps to `datetime.timedelta`.
Example: `5 04:03:02.123456` → `80 00 00 05 40 3f 3e 87 5b ca 00`.

### 11.7 BINARY_FLOAT / BINARY_DOUBLE

4-byte (float) / 8-byte (double) IEEE-754 in Oracle's **order-preserving** form
so the raw bytes sort the same as the numbers:

- **Encode**: if the value is positive, set the high (sign) bit; if negative,
  invert every bit.
- **Decode**: if the high bit is set, the value was positive — clear it; else
  the value was negative — invert every bit. Then read as IEEE-754.

Example: `1.5` (IEEE `3fc00000`) → `bfc00000`; `-2.25` (IEEE `c0100000`) →
`3fefffff`. `inf` / `nan` / `-0.0` round-trip; binding them requires the native
binary types (NUMBER cannot represent them).

### 11.8 ROWID

A REF/physical rowid (TNS type 11) is read from RXD as: a 1-byte present
indicator (0 / 0xff = NULL), then Object ID (UB4), File# (UB2), an unused UB1,
Block Number (UB4), Slot Number (UB2). Rendered as the 18-character extended
rowid: base-64 (`A-Z a-z 0-9 + /`) with fixed field widths 6+3+6+3 over
object / file / block / slot. Example: object 44681, file 4, block 8591,
slot 0 → `AAAK6JAAEAAACGPAAA` (matches `ROWIDTOCHAR`).

A **UROWID** (universal / logical rowid, TNS type 208 — e.g. the rowid of an
index-organized table) uses the same RXD framing as a LOB column: `ub4
num_bytes`, a 1-byte length echo, then `num_bytes` raw rowid bytes. The first
byte is a type tag; the printable form is `"*"` + standard base-64 of the
remaining bytes (no `=` padding). Example: value
`02 04 01 00 19 83 02 c1 02 fe` → `*BAEAGYMCwQL+` (the trailing `c1 02` is the
table's NUMBER primary key, since an IOT rowid is logical). NULL when
`num_bytes` is 0.

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

pyoracle's row decoder reads the LOB column as `ub4 num_bytes |
DALC locator_block`. The locator block (the locator metadata plus any
inline content section) is a **DALC** (`§12.2`): a single length-prefixed
chunk while the block stays under 254 bytes, or the `0xFE` chunked form
(length-prefixed sub-chunks terminated by a zero length) once it reaches
254. The block crosses 254 bytes when the LOB's content is woven inline
into the locator — for medium CLOBs, and for NCLOBs at half the character
count because their inline content is UTF-16BE (two bytes per character).
Decoding the block as a DALC (not as a 1-byte size echo + `num_bytes` raw
bytes, which only matched the single-chunk case) is what makes those
mid-size inline LOBs decode instead of spilling content bytes into the
token stream (#37). The reassembled locator is exactly what the server
expects back as the source pointer in a `TTI_LOBOPS` READ. NULL LOBs
(single `0x00` byte) come back as Python `None`; non-NULL LOBs come back
as `oracle.lob.LOB` objects that `Cursor.execute` automatically resolves
to `str` (CLOB) or `bytes` (BLOB) via `LOB.read()`.

Confirmed against XE 11g captures: `num_bytes` scales with content
as `102 + 2 × utf16_chars` for CLOBs and `102 + content_bytes` for
BLOBs. `LOB.read()` issues `TTI_LOBOPS` READ (`§14`) and decodes the
returned chunk as UTF-16BE for CLOB or surfaces raw bytes for BLOB.
EMPTY_CLOB() / EMPTY_BLOB() short-circuit without a round-trip.
The same path handles both inline-content LOBs and out-of-line LOBs
uniformly (the server packs content inline or fetches it from storage
as needed — that detail is opaque to the client).

### 11.10 LONG / LONG RAW

A LONG (TNS type 8) or LONG RAW (type 24) column in RXD is a chunked value
followed by **two trailing `ub4` indicators** (the actual / return lengths,
`0` / `0` for an ordinary value):

```
0x00            NULL, no body
0xfe            chunked: repeated [ub1 length][bytes] until a zero-length chunk
else            ub1 length + that many bytes
ub4 ub4         two trailing indicators (skip)
```

Large values are split into many ≤253-byte chunks (XE uses 64-byte chunks),
not one big chunk. LONG decodes to `str` (charset-aware), LONG RAW to `bytes`,
NULL to `None`. Confirmed against XE 11g (NULL, single-chunk, a 700-byte
multi-chunk value, and a LONG that is not the last column).

## 12. Wire Encoding Primitives

### 12.1 Variable-Length Integer (SB4/SB2)

A compact encoding for 32-bit integers: a length byte followed by that
many big-endian magnitude bytes.

| Value         | Encoding                         |
|---------------|----------------------------------|
| 0             | `0x00`                           |
| 0..255        | `0x01, <byte>`                   |
| 0..65535      | `0x02, <hi>, <lo>`               |
| 0..16777215   | `0x03, <b2>, <b1>, <b0>`        |
| 0..4294967295 | `0x04, <b3>, <b2>, <b1>, <b0>`  |
| Negative      | `(0x80 | len), <len big-endian magnitude bytes>` |

For a negative value the high bit of the length byte is set and the low
7 bits give the magnitude byte count, so the magnitude can span several
bytes — e.g. NUMBER scale `-127` arrives as `0x81 0x7f` and `-256` as
`0x82 0x01 0x00`.

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

pyoracle advertises and decodes **AL32UTF8 (873)** — real UTF-8 — for both the
database and national charset (see §4.1). Note the trap: Oracle's `UTF8` (871)
is **not** the same as AL32UTF8; it is CESU-8, which mis-encodes
supplementary-plane characters. pyoracle never advertises 871. National-charset
columns (`NCHAR` / `NVARCHAR2` / `NCLOB`, charset id 2000 / AL16UTF16, CharsetForm
2) are converted by the server to AL32UTF8 on the wire and decode through the
same UTF-8 path.

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

The `LOB_DATA` chunk is length-prefixed with the version-gated
`bytes_with_length` form (§6.4): 11g uses single-byte chunk lengths,
12c+ a `0xFE` marker with `ub4` chunk lengths and a zero terminator.
`_read_lob_response` walks tokens until the trailing OER; that OER opens
with `04 01 01` (TTI_OER + `call_status` ub4 = 1) and then a per-call
end-to-end seq# whose length byte varies, so the stop scan keys on the
`04 01 01` prefix rather than a fixed 4th byte. Without the `ub4`
chunk-length handling on 12c the content desyncs and the reader blocks
waiting for a packet that never comes (the LOB fetch hangs).

### 14.4 Implementation status

pyoracle implements `TTI_LOBOPS` READ (`encode_dictionary_lobops`
in `oracle/tns.py`, response handling in
`OracleConnect._read_lob_response`) and uses it transparently from
`LOB.read()` for every non-empty LOB cell. Worth noting:

- **Don't send `amount = 0xFFFFFFFF`.** XE 11g quietly stops
  responding when the request asks for `uint32` max. Use a large but
  finite value instead — pyoracle defaults to `0x40000000` (1 GiB),
  comfortably past any realistic LOB while staying inside signed
  int32.
- **Locator bytes go on the wire as-is.** The bytes pyoracle extracts
  from the RXD column (after skipping the `ub4 num_bytes` prefix +
  the 1-byte size echo) are exactly what the server expects as the
  source pointer; no DALC wrapping, no length prefix beyond what the
  request body already carries.
- **The response carries `TTI_LOB` (content) + `TTI_RPA`
  (updated locator) + `TTI_OER` (call status)** in a single packet.
  pyoracle decodes the LOB chunk(s) and skips past the RPA block by
  scanning forward for the OER `04 01 XX 01` signature — the RPA
  layout is complex enough that we don't try to parse it, and we
  don't need anything out of it.

LOB *writes* (LOB binds on INSERT / UPDATE) do **not** need a
`TTI_LOBOPS` WRITE round-trip. They go through the regular VARCHAR2 / RAW
bind path: a value larger than 4000 bytes is sent as a streamed LONG
(the OAC max-size is set to the value's length, §5.3), and the server
writes that streamed value straight into the CLOB / BLOB column. Once a
bind exceeds the SDU the request simply fragments across TNS packets
(§1.4, data flags `0x0020` on non-final fragments — the fragmentation fix
in #8). This round-trips CLOB and BLOB binds byte-for-byte at arbitrary
size; the integration suite covers 50 KiB and 500 KiB of both on 11g and
12c+.

A client-side temp-LOB path (`CREATE_TEMP` → `WRITE` → bind the locator →
`FREE_TEMP`, opcodes in §14.2) is therefore unnecessary for binds and is
not implemented. For the record, the request shapes were reverse-engineered
against a 21c capture and verified there, but Oracle XE 11g rejects the
`CREATE_TEMP` request outright (immediate FIN, no error packet) and no thin
client speaks that opcode to 11g, so there is no reference to finish it
against — and the streamed-LONG path above makes it moot.

## 15. TNS Marker Protocol

TNS_MARKER packets serve as break/attention signals. The marker body is 3 bytes:

- `0x01, 0x00, 0x02`: Standard marker. Client responds with the same marker pattern.
- `0x01, 0x00, 0x01`: Break marker. Triggers a read-timeout mode where the client reads with a short timeout to collect remaining data.

## 16. Sequence Numbers

Each TTC function call includes an incrementing sequence number (1 byte, wrapping from 127 back to 1). The sequence number is managed per-connection and ensures ordered request processing.

## 17. Native JSON (OSON)

Oracle 21c+ stores a native `JSON` column as a BLOB-backed **OSON** image (a
compact binary JSON). The column's TNS data type is **119** (`TNS_TYPE_JSON`).
On the wire it behaves exactly like a BLOB: the RXD row carries a LOB *locator*,
and the OSON image is fetched over `TTI_LOBOPS` (§14). pyoracle reads it through
the normal LOB locator path and then decodes the OSON in `oracle/oson.py`.

The format below was reverse-engineered from images captured off a live 21c
server, each with known content. An OSON image is:

```
magic "FF 4A 5A" | version (1) | flags (ub2) | body
```

`flags & 0x2000` marks a **tree** image (object/array). Otherwise the body is a
single **bare scalar**: `reserved(ub1) | value_size(ub1) | <scalar node>`.

A tree body is:

```
num_fnames (ub1) | fnames_seg_size (ub2) | tree_seg_size (ub2) | reserved (ub2)
hash_array     (num_fnames × ub1)   one hash byte per field name (unused on read)
offset_array   (num_fnames × ub2)   field-id → offset into fnames_seg
fnames_seg                          field names, each <len(ub1)><utf8 bytes>
tree_seg                            the node tree, root node at offset 0
```

A field id is 1-based: `offset_array[id - 1]` locates the field's name in
`fnames_seg`.

### 17.1 Node encoding

| Tag byte            | Node                                                        |
|---------------------|-------------------------------------------------------------|
| `0x00`–`0x1F`       | short string, length = tag, then that many UTF-8 bytes      |
| `0x20`–`0x2F`       | number, Oracle NUMBER of `(tag − 0x1F)` bytes               |
| `0x30` / `0x31` / `0x32` | `null` / `true` / `false`                              |
| `0x33`              | string, `ub1` length prefix, then UTF-8 bytes               |
| `0x34`              | number, `ub1` length prefix, then Oracle NUMBER bytes       |
| `(tag & 0xC0) == 0x80` | object: `count(ub1)`, `field_id(ub1)×count`, `value_offset(ub2)×count` |
| `(tag & 0xC0) == 0xC0` | array: `count(ub1)`, `value_offset(ub2)×count`           |

Container value-offsets are relative to the tree segment start. Objects list
their `(field_id, value_offset)` pairs in document order.

**Extended scalar nodes (#69).** JSON can carry Oracle-native scalars (e.g. via
`JSON_SCALAR(<native>)`). Each is a tag byte followed by a fixed-width Oracle
binary value (no length prefix — the width is intrinsic), decoded by the same
routines as the column wire forms; binary float/double are in the
order-preserving ("sortable") form:

| Tag    | Type                    | Width |
|--------|-------------------------|-------|
| `0x36` | BINARY_DOUBLE           | 8     |
| `0x7F` | BINARY_FLOAT            | 4     |
| `0x3C` | DATE                    | 7     |
| `0x39` | TIMESTAMP               | 11    |
| `0x7C` | TIMESTAMP WITH TIME ZONE| 13    |
| `0x3D` | INTERVAL YEAR TO MONTH  | 5     |
| `0x3E` | INTERVAL DAY TO SECOND  | 11    |
| `0x7D` | DATE (ub4-offset images)| 7     |

**Width selectors (#69).** Three independent width choices:
- *Container value-offsets* are `ub2` only when the header flag `0x04` is set
  (server `JSON_OBJECT` / `JSON()` literals); oracledb-produced images clear it
  (flags `0x2102`) and use `ub4`. Reading the wrong width walks offset 0 →
  infinite recursion, so the decoder picks the width from the flag.
- *`num_fnames`* is `ub2` (else `ub1`) when the header flag `0x0400` is set —
  i.e. the document has > 255 field names.
- A *container node tag* with the `0x08` bit (object `0x88`/`0xac` vs `0x84`/
  `0xa4`) has a `ub2` count and `ub2` field-ids; otherwise `ub1`.

> **Not yet covered** (raises `OsonError` rather than decode wrong): `ub4`
> *segment sizes* — fnames / tree segments larger than 64 KiB. Niche; the
> common large-document and oracledb cases are handled.
>
> Multi-row JSON `SELECT`s ride the same LOB-locator path as multi-row LOB
> reads and share the #45 desync limitation under load — single-row reads are
> reliable.

### 17.2 Binds (#50, #70)

A bare Python `dict` is auto-detected as JSON (it has no other bind meaning);
wrap a `list` / scalar in `oracle.JSON(value)` to bind it as JSON too, since a
bare `list` means a VECTOR and bare scalars bind as their native SQL types.
`Decimal` binds as a JSON number (integral values stay exact, others via
`float`), matching the decoder, which returns JSON numbers as `Decimal`.

pyoracle prefers a **native binary OSON** bind (#70, the inverse of the §17.1
decoder in `oracle/oson.py:encode_oson`). It is sent exactly like the native
VECTOR bind (§18.1): the bind OAC is the JSON one (`JSON_BIND_OAC`, type 119
with a 32 MiB max length, captured from python-oracledb on 21c) and the value
carries the same 19-byte LOB-backed descriptor, the image length (ub2), 22 zero
bytes, then the OSON image over the 12c length framing. The encoder writes the
compact small-document form — the object/array node uses a ub1 count, ub1
field-ids and ub2 value-offsets; field-name hashes are sent as zero (the server
accepts that, verified by round-trip). Both fv16 (21c) and fv17 (23ai) accept
it.

`encode_oson` raises `OsonError` for anything it does not encode compactly —
strings over 255 bytes, objects/arrays over 255 entries, segments over 64 KiB —
and the bind path then falls back to the **text cast** (#50): serialise to JSON
text (`json.dumps`, `ensure_ascii=False`) and bind it as a `VARCHAR` the server
casts to `JSON`. So a wide (>255-key) document still binds, via the text path,
and reads back through the §17.1 wide-object decode. (Reading back a document
with a string longer than the decoder's ub1-string support is the separate,
pre-existing long-string decode gap, not a bind limitation.)

## 18. Native VECTOR (23ai+)

Oracle 23ai+ stores a native `VECTOR` column as a binary image delivered, like
JSON (§17), through a LOB locator: the RXD row carries a locator and the image
is fetched over `TTI_LOBOPS` (§14). The column's TNS data type is **127**
(`TNS_TYPE_VECTOR`). pyoracle reads it through the normal LOB locator path and
decodes the image in `oracle/vector.py`.

The format below was reverse-engineered from images captured off a live 23ai
server, each with known content. A VECTOR image is:

```
magic 0xDB | version (ub1) | flags (ub2) | element_type (ub1) | num_elements (ub4)
[ norm (8 bytes, present when flags & 0x10) ]
elements ...
```

`version` is `0x00` for FLOAT32/FLOAT64/INT8 and `0x01` for BINARY; the decoder
ignores it. The 8-byte `norm` is a cached magnitude (sortable-encoded, see
below) that is not part of the value and is skipped.

| `element_type` | Type     | Element encoding                                        |
|----------------|----------|---------------------------------------------------------|
| `2`            | FLOAT32  | 4 bytes, order-preserving ("sortable") float            |
| `3`            | FLOAT64  | 8 bytes, order-preserving ("sortable") float            |
| `4`            | INT8     | 1 byte, plain two's-complement                          |
| `5`            | BINARY   | bits packed 8/byte; see below                           |

**Sortable float** (FLOAT32/64): the encoding makes a byte-wise compare order
values numerically — for a positive value the sign bit is set, for a negative
value every bit is inverted. Reverse it by: if the top bit is set, clear it;
otherwise invert all bits. Then read the result as a big-endian IEEE-754 float.

**BINARY** (bit vectors): `num_elements` is the **dimension (bit) count**, not a
byte count, and the payload is those bits packed 8 to a byte —
`ceil(num_elements / 8)` bytes. pyoracle surfaces the packed bytes verbatim as a
list of ints, matching the form a `VECTOR(n, BINARY)` literal takes (e.g.
`'[170, 1]'` for a 16-dim vector stores bytes `AA 01` and reads back `[170, 1]`).

Captured reference images:

```
[1.5, 2.5, 3.5]  FLOAT32  db 00 0012 02 00000003 c012388ac0059c28 ...
[1, -2, 3, -4]   INT8     db 00 0012 04 00000004 c015e8add236a58f 01 fe 03 fc
[170]            BINARY   db 01 0010 05 00000008 8000000000000000 aa
[170, 1]         BINARY   db 01 0010 05 00000010 8000000000000000 aa 01
```

### 18.1 Binds (#55 / #62)

pyoracle binds a vector with the **native binary image** (matching
python-oracledb). The full exec bind for a vector is `OAC | TTI_RXD | value`:

- **OAC** (`encode_token_oac`): a fixed 25-byte block — type 127, the *cont-flag*
  field `0x02000000`, and the *oaccolid* field set to the 1 MiB max length:
  `7f 01 00 00 | 04 00100000 | 00 | 04 02000000 | 00 00 00 00 | 04 00100000 | 00`.
  Without the `0x02000000` flag the server rejects the inline value (ORA-03120);
  a too-short OAC desyncs (ORA-03106).
- **Value** (`encode_token_rxd`, after the `TTI_RXD`=0x07 token): a fixed 19-byte
  **descriptor** (`01 28 28 00 26 00 04 61 08 00 00 00 01 00 00 00 00 00 00` —
  the same one python-oracledb uses for any LOB-backed inline bind, so #70 JSON
  reuses it), then the **image length (ub2)**, **22 zero bytes**, then the image
  framed like RAW (`encode_chr`: a single length byte < 254, else the `0xFE`
  marker + `ub4` chunks). Both constants are stable across element types and
  sizes; works at field version 16 and 17.
- **Image** (`encode_vector`): the read image (§18) with the 8-byte norm sent as
  **zeros** (the server recomputes it). FLOAT32/64 use the sortable encoding,
  INT8 raw bytes, BINARY packed bytes; a SparseVector emits the §18.2 sparse
  image. Dense `list`/`tuple` → FLOAT32; an `array.array` maps by typecode.

### 18.2 SPARSE vectors (#68)

A `VECTOR(n, T, SPARSE)` column stores only the non-zero elements. Its image is
**version `2`** with the **`0x20`** flag set, and after the header + norm carries:

```
count (ub2) | indices (ub4 × count) | values (element × count)
```

`num_elements` (header) is the total dimension count; `count` is the number of
stored elements; the values use the same per-element encoding as a dense image
(sortable FLOAT32/64, raw INT8). pyoracle decodes it to an `oracle.SparseVector`
(`num_dimensions`, `indices`, `values`) and binds one back natively via §18.1
(the sparse image carries the same OAC + descriptor). Captured on 23ai across
FLOAT32/INT8 and a 300-dim vector (index 299 confirms the ub4 indices).

> As with JSON, multi-row VECTOR `SELECT`s share the #45 LOB desync limitation
> under load; single-row reads are reliable.
