# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

from enum import Enum

TNS_CONNECT = 1
TNS_ACCEPT = 2
TNS_ACK = 3
TNS_REFUSE = 4
TNS_REDIRECT = 5
TNS_DATA = 6
TNS_NULL = 7
TNS_ABORT = 9
TNS_RESEND = 11
TNS_MARKER = 12
# Marker packet sub-types (#144). A break/cancel is an in-band INTERRUPT marker
# packet (type 12, body [1, 0, marker_type]) -- the universally-honoured way to
# interrupt a running call; the OOB urgent byte is an optimisation many servers
# (and rootless container networks) don't deliver.
TNS_MARKER_TYPE_BREAK = 1
TNS_MARKER_TYPE_RESET = 2
TNS_MARKER_TYPE_INTERRUPT = 3
# Global service option in the accept packet: the server can receive an
# out-of-band break (attention). When set we prefer OOB over the in-band
# marker for cancel()/call_timeout (#144).
TNS_GSO_CAN_RECV_ATTENTION = 0x0400
# Protocol-version-319 / large-SDU handshake (#155). seerdb advertises version
# 319 in the CONNECT; a server whose negotiated version is >= 315 switches to the
# 4-byte ("large") packet length, and a >= 318 server's ACCEPT carries an
# extended flags2 word whose HAS_END_OF_RESPONSE bit lets the client opt into the
# end-of-response framing that pipelining (#132) needs.
TNS_VERSION_MIN_LARGE_SDU = 315  # 4-byte packet length from here up
TNS_VERSION_MIN_OOB_CHECK = 318  # accept carries the extended flags2
TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE = 0x02000000
TNS_CCAP_END_OF_RESPONSE = 0x20  # CCAP_TTC4 opt-in bit (#155/#132)
TTI_END_OF_RESPONSE = 29  # per-response terminator marker
# Request pipelining (#132). Several calls are sent back-to-back, each numbered
# with a ub8 token, then a PIPELINE_END message; the server tags each response
# with a matching TOKEN (33) marker and ends it with the EOR (29) marker.
TTI_MSG_TYPE_PIGGYBACK = 0x11  # piggyback message type (17)
TTI_TOKEN = 33  # response correlation marker
TNS_FUNC_PIPELINE_BEGIN = 199  # begin-pipeline piggyback
TNS_FUNC_PIPELINE_END = 200  # end-of-pipeline message
TNS_DATA_FLAGS_BEGIN_PIPELINE = 0x1000  # first pipelined packet
TNS_DATA_FLAGS_END_OF_RESPONSE = 0x2000  # the flag that terminates a response body
TNS_DATA_FLAGS_END_OF_REQUEST = 0x0800  # a pipelined call expecting a result
TNS_DATA_FLAGS_MORE = 0x0020  # non-final DATA fragment: more of the message follows
TNS_DATA_FLAGS_EOF = 0x0040  # EOF: final empty DATA packet, releases the session
TNS_PIPELINE_MODE_CONTINUE_ON_ERROR = 1
TNS_PIPELINE_MODE_ABORT_ON_ERROR = 2

# The wire's escape / null-value sentinel (0xFD). As a value-slot marker it flags
# an absent value — e.g. sqlplus / thick-OCI sends `fd 01` in an OUT bind's value
# slot (§ OUT-bind request marker), the wire carrying no bind direction.
TNS_ESCAPE_CHAR = 0xFD
# The longest value a single length byte may announce (python-oracledb's
# TNS_MAX_SHORT_LENGTH). The three bytes above it are markers, not lengths:
# 253 (0xFD) is the escape above, 254 (0xFE) opens a chunked value and 255
# (0xFF) is NULL. A 253-byte value behind a plain length byte is an escape where
# the server expects a length, and 12c+ rejects the call with ORA-03125 (#707).
# The same markers frame object-image attributes (dbobject).
TNS_MAX_SHORT_LENGTH = 252
TNS_LONG_LENGTH_INDICATOR = 0xFE
TNS_NULL_LENGTH_INDICATOR = 0xFF

# Server-side scrollable cursors (#181). The execute al8i4 array carries the
# scroll request: al8i4[9] gains the SCROLLABLE + NO_CANCEL_ON_EOF exec flags
# (keep the cursor open past EOF so it can scroll back), al8i4[10] the fetch
# orientation, al8i4[11] the 1-based fetch position (ABSOLUTE / RELATIVE).
TNS_EXEC_FLAGS_SCROLLABLE = 0x02
TNS_EXEC_FLAGS_NO_CANCEL_ON_EOF = 0x80
# al8i4[9] bit a query execute sets (oracledb-thin: implicit result sets); its
# absence is what the DBMS_SQL.RETURN_RESULT path checks for (#121).
TNS_EXEC_FLAGS_IMPLICIT_RESULTSET = 0x8000
# Exec-options word bit for a re-execute that re-runs the statement. A scroll
# re-execute must NOT set it: oracledb-thin's scroll re-execute uses FETCH-only
# options (0x8040), and leaving EXECUTE (0x20) on makes the server re-run the
# query — resetting the result set so the scroll orientation positions from the
# top and every orientation comes back empty. set_opts always forces 0x20 on for
# a Flag=0 select, so encode_dictionary_exec clears it for a scroll re-execute.
TNS_EXEC_OPTION_EXECUTE = 0x20
# The other exec-options word bits the execute encoders compose.
TNS_EXEC_OPTION_PARSE = 0x01
TNS_EXEC_OPTION_BIND = 0x08
TNS_EXEC_OPTION_FETCH = 0x40
TNS_FETCH_ORIENTATION_CURRENT = 0x01
TNS_FETCH_ORIENTATION_NEXT = 0x02
TNS_FETCH_ORIENTATION_FIRST = 0x04
TNS_FETCH_ORIENTATION_LAST = 0x08
TNS_FETCH_ORIENTATION_PRIOR = 0x10
TNS_FETCH_ORIENTATION_ABSOLUTE = 0x20
TNS_FETCH_ORIENTATION_RELATIVE = 0x40

# End-to-end application tracing attributes (#183): a SET_END_TO_END_ATTR
# piggyback (func TTI_SCID=135) tells the server which of module / action /
# client_identifier / client_info / dbop changed and carries the new values.
# Flag bits (which attributes the piggyback updates).
TNS_FUNC_SET_END_TO_END_ATTR = 135  # == TTI_SCID, 0x87
TNS_END_TO_END_CLIENT_IDENTIFIER = 0x0001
TNS_END_TO_END_MODULE = 0x0008
TNS_END_TO_END_ACTION = 0x0010
TNS_END_TO_END_CLIENT_INFO = 0x0100
TNS_END_TO_END_DBOP = 0x0200

# End-user security context (#460, milestone #29): a piggyback (func 205) that
# attaches an end-user identity / authorization context to the session for Deep
# Data Security (proxy / real-application-user scenarios). Carries a single
# keyword-value pair whose value is the OSON image of the context. Negotiated
# via the FEATURE_BACKPORT2 capability bit; the reference thin client restricts
# it to TLS (tcps) transports.
TNS_FUNC_END_USER_SECURITY_CTX = 205  # 0xCD
TNS_SECURITY_CONTEXT_ATTACH_FLAG = 0x01

# Request boundaries (#464): a SESSION_STATE piggyback (func 176) that tells the
# server when a pooled logical request begins / ends, so it can reset or reclaim
# session state between requests. Body is ub8(state | EXPLICIT_BOUNDARY).
TNS_FUNC_SESSION_STATE = 176  # 0xB0
TNS_SESSION_STATE_REQUEST_BEGIN = 0x04
TNS_SESSION_STATE_REQUEST_END = 0x08
TNS_SESSION_STATE_EXPLICIT_BOUNDARY = 0x40

TNS_ATTENTION = 13
TNS_CONTROL = 14
TNS_MAX = 19

TNS_TYPE_CHAR = 96
TNS_TYPE_VARCHAR = 1
TNS_TYPE_VCS = 9
TNS_TYPE_NUMBER = 2
TNS_TYPE_FLOAT = 4
TNS_TYPE_VARNUM = 6
TNS_TYPE_LONG = 8
TNS_TYPE_LONGRAW = 24
TNS_TYPE_RAW = 23
TNS_TYPE_VBI = 15
TNS_TYPE_RID = 11
TNS_TYPE_ROWID = 104
TNS_TYPE_UROWID = 208
TNS_TYPE_REFCURSOR = 102
TNS_TYPE_RSET = 116
TNS_TYPE_DATE = 12
TNS_TYPE_TIMESTAMP = 180
TNS_TYPE_TIMESTAMPTZ = 181
TNS_TYPE_TIMESTAMPLTZ = 231
TNS_TYPE_INTERVALYM = 182
TNS_TYPE_INTERVALDS = 183
TNS_TYPE_CLOB = 112
TNS_TYPE_BLOB = 113
TNS_TYPE_BFILE = 114
TNS_TYPE_BFLOAT = 100
TNS_TYPE_BDOUBLE = 101
TNS_TYPE_ADT = 109
TNS_TYPE_REF = 111
TNS_TYPE_JSON = 119  # native JSON (OSON), 21c+ (#30)
TNS_TYPE_BOOLEAN = 252  # native SQL BOOLEAN, 23ai+ (#54)
TNS_TYPE_VECTOR = 127  # native VECTOR, 23ai+ (#55)

TTI_PRO = 1
TTI_DTY = 2
TTI_FUN = 3
TTI_OER = 4
TTI_RXH = 6
TTI_RXD = 7
TTI_RPA = 8
TTI_STA = 9
TTI_ROW = 10
TTI_IOV = 11
TTI_UDS = 12
TTI_OAC = 13
TTI_LOB = 14
TTI_WRN = 15
TTI_DCB = 16
TTI_PFN = 17
TTI_FOB = 19
TTI_BVC = 21
TTI_IRD = 27  # implicit result-set describe (DBMS_SQL.RETURN_RESULT, #121)

# Two-phase commit / XA (#131). Function codes + operations + states.
TNS_FUNC_TPC_TXN_SWITCH = 103  # tpc_begin (start) / tpc_end (detach)
TNS_FUNC_TPC_TXN_CHANGE_STATE = 104  # tpc_prepare / commit / rollback / forget
TNS_TPC_TXN_START = 0x01
TNS_TPC_TXN_DETACH = 0x02
TNS_TPC_TXN_COMMIT = 0x01
TNS_TPC_TXN_ABORT = 0x02
TNS_TPC_TXN_PREPARE = 0x03
TNS_TPC_TXN_FORGET = 0x04
TNS_TPC_TXN_STATE_PREPARE = 0
TNS_TPC_TXN_STATE_REQUIRES_COMMIT = 1
TNS_TPC_TXN_STATE_COMMITTED = 2
TNS_TPC_TXN_STATE_ABORTED = 3
TNS_TPC_TXN_STATE_READ_ONLY = 4
TNS_TPC_TXN_STATE_FORGOTTEN = 5
# tpc_begin flags
TPC_BEGIN_NEW = 0x00000001
TPC_BEGIN_JOIN = 0x00000002
TPC_BEGIN_RESUME = 0x00000004
TPC_BEGIN_PROMOTE = 0x00000008
# tpc_end flags
TPC_END_NORMAL = 0x00000000
TPC_END_SUSPEND = 0x00100000
# Sessionless transactions (#133, 23ai). They reuse the func-103 switch message
# with the SESSIONLESS flag OR'd into the start/resume/detach flags, and a fixed
# magic format-id carried in the XID slot (the user txn id goes in the gtrid).
# Confirmed on the wire (23ai 23.26) against the oracledb-thin reference.
TPC_TXN_FLAGS_SESSIONLESS = 0x00000010
TNS_TPC_SESSIONLESS_FORMAT_ID = 0x4E5C3E
TNS_SESSIONLESS_TXN_ID_MAX = 64

# DRCP session purity (#130).
PURITY_DEFAULT = 0
PURITY_NEW = 1
PURITY_SELF = 2

# Server-side piggyback (#130): a response token (23) the server prepends to
# carry session-state updates — DRCP-pooled sessions get SESS_RET + OS_PID_MTS.
TTI_SVR_PIGGYBACK = 23
TNS_SERVER_PIGGYBACK_QUERY_CACHE_INVALIDATION = 1
TNS_SERVER_PIGGYBACK_OS_PID_MTS = 2
TNS_SERVER_PIGGYBACK_TRACE_EVENT = 3
TNS_SERVER_PIGGYBACK_SESS_RET = 4
TNS_SERVER_PIGGYBACK_SYNC = 5
TNS_SERVER_PIGGYBACK_LTXID = 7
TNS_SERVER_PIGGYBACK_AC_REPLAY_CONTEXT = 8
TNS_SERVER_PIGGYBACK_EXT_SYNC = 9
TNS_SERVER_PIGGYBACK_SESS_SIGNATURE = 10

# Advanced Queuing (#128).
TNS_FUNC_AQ_ENQ = 121
TNS_FUNC_AQ_DEQ = 122
TNS_FUNC_ARRAY_AQ = 145
TNS_AQ_ARRAY_ENQ = 0x01
TNS_AQ_ARRAY_DEQ = 0x02
TNS_AQ_ARRAY_FLAGS_RETURN_MESSAGE_ID = 0x01
TNS_AQ_MESSAGE_VERSION = 1
TNS_AQ_MESSAGE_ID_LENGTH = 16
TNS_AQ_EXT_KEYWORD_AGENT_NAME = 64
TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS = 65
TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL = 66
TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID = 69
TNS_KPD_AQ_BUFMSG = 0x02
TNS_KPD_AQ_EITHER = 0x10
TNS_AQ_MSG_PERSISTENT = 1
TNS_AQ_MSG_BUFFERED = 2
TNS_AQ_MSG_PERSISTENT_OR_BUFFERED = 3
# dequeue mode / navigation / visibility / wait
TNS_AQ_DEQ_BROWSE = 1
TNS_AQ_DEQ_LOCKED = 2
TNS_AQ_DEQ_REMOVE = 3
TNS_AQ_DEQ_REMOVE_NODATA = 4
TNS_AQ_DEQ_FIRST_MSG = 1
TNS_AQ_DEQ_NEXT_TRANSACTION = 2
TNS_AQ_DEQ_NEXT_MSG = 3
TNS_AQ_DEQ_IMMEDIATE = 1
TNS_AQ_DEQ_ON_COMMIT = 2
TNS_AQ_ENQ_IMMEDIATE = 1
TNS_AQ_ENQ_ON_COMMIT = 2
TNS_AQ_DEQ_NO_WAIT = 0
TNS_AQ_DEQ_WAIT_FOREVER = 0xFFFFFFFF

TTI_OPEN = 2
TTI_EXEC = 4
TTI_FETCH = 5
TTI_LOGOFF = 9
TTI_COMON = 12
TTI_COMOFF = 13
TTI_COMMIT = 14
TTI_ROLLBACK = 15
TTI_CANCEL = 20
TTI_DSCRARR = 43
TTI_STRT = 48
TTI_STOP = 49
TTI_VERSION = 59
TTI_K2RPC = 67
TTI_ALL7 = 71
TTI_SQL7 = 74
TTI_3LOGON = 81
TTI_3LOGA = 82
TTI_KOD = 92
TTI_ALL8 = 94
TTI_LOBOPS = 96
TTI_DNY = 98
TTI_TXSE = 103
TTI_TXEN = 104
TTI_OCCA = 105
TTI_80SES = 107
TTI_AUTH = 115
TTI_SESS = 118
TTI_DESCRIBE = 119  # sqlplus `DESCRIBE <object>` (thick-OCI describe-object call)
TTI_CANA = 120
TTI_KPN = 125
TTI_OTCM = 127
TTI_SCID = 135
TTI_SPFP = 138
TTI_KPFC = 139
TTI_PING = 147

# Further Oracle TTC function / message-type codes seerdb does not dispatch yet —
# cataloged so the dispatch table and downstream RE have names, not bare numbers.
TNS_FUNC_REEXECUTE_AND_FETCH = 78  # combined re-execute + fetch round-trip
TNS_FUNC_DIRECT_PATH_PREPARE = 128
TNS_FUNC_DIRECT_PATH_LOAD_STREAM = 129
TNS_FUNC_DIRECT_PATH_OP = 130  # direct-path load (SQL*Loader path)
TNS_FUNC_SET_SCHEMA = 152  # ALTER SESSION SET CURRENT_SCHEMA fast-path
TNS_FUNC_SESSION_GET = 162  # DRCP pooled-session acquire (#130)
TNS_FUNC_SESSION_RELEASE = 163  # DRCP pooled-session release (#130)
TNS_FUNC_NOTIFY = 187  # CQN / AQ notification delivery (#129)
TNS_MSG_TYPE_ONEWAY_FN = 26  # fire-and-forget call, no response expected
TNS_MSG_TYPE_RENEGOTIATE = 28  # server asks the client to renegotiate (TLS / caps)

# TNS_CCAP_FIELD_VERSION_* values (the byte written at CCAP_FIELD_VERSION). The
# negotiated TTC field version gates the auth verifier and the version-specific
# wire formats. Kept here in the leaf constants module (rather than seerdb.common.tns)
# so seerdb.client.cursor can import the 12.1 threshold from a lightweight leaf
# without dragging in the whole encoder.
FIELD_VERSION_9_2 = 2  # Oracle 9i (pre-10g O3LOGON thin auth, #90)
FIELD_VERSION_10_2 = 4  # Oracle 10g — oldest tier using the O5LOGON path
FIELD_VERSION_11_2 = 6
FIELD_VERSION_12_1 = 7
FIELD_VERSION_12_2 = 8
FIELD_VERSION_12_2_EXT1 = 9
FIELD_VERSION_19_1 = 12
FIELD_VERSION_19_1_EXT1 = 13  # written inside the FAST_AUTH envelope (#89)
FIELD_VERSION_20_1 = 14  # AQ JSON-payload pointer gate (#128)
FIELD_VERSION_21_1 = 16
FIELD_VERSION_23_1 = 17  # highest the LEGACY 3-message handshake reaches
FIELD_VERSION_23_4 = 24  # 23ai max; reached only via FAST_AUTH (#89)

# Oracle 23ai "fast auth" (#89): a single TNS DATA packet (message type 0x22)
# bundling the protocol, datatypes, and OSESSKEY messages in one round trip. It is
# the only way to advertise CCAP_FIELD_VERSION >= 18 — the legacy three-message
# handshake is rejected with ORA-03146 at fv >= 18. seerdb gates on the server's
# own field version (learned from its PRO reply, 23ai advertises 27), not an ACCEPT
# flag: at the protocol version seerdb sends (313) the ACCEPT carries no flag.
TNS_MSG_TYPE_FAST_AUTH = 0x22
TNS_SERVER_CONVERTS_CHARS = 0x01  # fast-auth envelope flag byte

DictionaryType = Enum(
    'DictionaryType',
    'auth chgpwd close description dty exec fetch lobops login pig pro sess spfp start stop tran',
)

# OALL8 execute-option bit that turns on array-DML batch-error mode: a per-row
# error is collected (in the OER batch-error arrays) instead of aborting the
# batch. ORed into the leading Opt word (#18).
TNS_EXEC_OPTION_BATCH_ERRORS = 0x80000

# Value the 12c+ OALL8 al8i4 array carries at element index 9 when array-DML
# row counts are requested (oracledb arraydmlrowcounts). oracledb always sends
# 0x8000 there; with arraydmlrowcounts it sets 0xC000 (the extra 0x4000 bit).
# seerdb's baseline is 0, so the whole 0xC000 is written when requested — the
# server's kpoal8Check rejects the al8pidmlrc pointer (below) as malformed
# (ORA-03137) without it. Reverse-engineered from an oracledb-thin capture (#18).
TNS_AL8I4_ARRAY_DML_ROWCOUNTS = 0xC000

TNS_LOB_OP_GET_LENGTH = 0x0001
TNS_LOB_OP_READ = 0x0002
TNS_LOB_OP_TRIM = 0x0020
TNS_LOB_OP_WRITE = 0x0040
TNS_LOB_OP_FILE_OPEN = 0x0100
TNS_LOB_OP_CREATE_TEMP = 0x0110
TNS_LOB_OP_FREE_TEMP = 0x0111
TNS_LOB_OP_FILE_CLOSE = 0x0200
TNS_LOB_OP_GET_CHUNK_SIZE = 0x4000
TNS_LOB_OP_OPEN = 0x8000
TNS_LOB_OP_CLOSE = 0x10000

# Bind OAC flag bits: every thin bind uses indicators; a PL/SQL associative-array
# bind (#122) also sets ARRAY, in the flag byte of the 12.2+ layout and in the
# second flag word of the 11g one (see encode_token_raw).
TNS_BIND_USE_INDICATORS = 0x01
TNS_BIND_ARRAY = 0x40

# Bind directions in the TTI_IOV response (one per bind, in bind order).
TNS_BIND_DIR_OUTPUT = 16
TNS_BIND_DIR_INPUT = 32
TNS_BIND_DIR_INPUT_OUTPUT = 48

ISO_LATIN_1_CHARSET = 31
UTF8_CHARSET = 871
AL32UTF8_CHARSET = 873
AL16UTF16_CHARSET = 2000

CharsetDict = {
    'we8iso8859p1': 31,
    'ee8iso8859p2': 32,
    'cl8iso8859p5': 35,
    'ee8mswin1250': 170,
    'cl8mswin1251': 171,
    'we8mswin1252': 178,
    'ja16euc': 830,
    'zhs16gbk': 852,
    'zht16big5': 865,
    'zht16mswin950': 867,
    'al32utf8': 873,
    'al16utf16': 2000,
}

DEFAULT_HOST = ''
DEFAULT_PORT = 1521
DEFAULT_SID = ''
# The packed release (major<<24 | minor<<20 | update<<12 | patch<<8) of the
# captured XE 11.2.0.2.0 server: the Mirror's 11.2 identity and the codec's
# default AUTH_VERSION_NO in an auth result.
SERVER_VERSION_11_2_0_2 = 0x0B200200

# Default Session Data Unit (0x2000). The negotiated packet payload size; both
# the client connect defaults and the server (Mirror) framing start here.
DEFAULT_SDU = 8192

CONN_STATE_DISCONNECTED = 0
CONN_STATE_CONNECTED = 1
CONN_STATE_AUTH_NEGOTIATE = 2
CONN_STATE_AUTHENTICATED = 3

MAX_SEQ_NUM = 127
