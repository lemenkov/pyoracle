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
TNS_TYPE_JSON = 119      # native JSON (OSON), 21c+ (#30)
TNS_TYPE_BOOLEAN = 252   # native SQL BOOLEAN, 23ai+ (#54)
TNS_TYPE_VECTOR = 127    # native VECTOR, 23ai+ (#55)

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
TTI_CANA = 120
TTI_KPN = 125
TTI_OTCM = 127
TTI_SCID = 135
TTI_SPFP = 138
TTI_KPFC = 139
TTI_PING = 147

# TNS_CCAP_FIELD_VERSION_* values (the byte written at CCAP_FIELD_VERSION). The
# negotiated TTC field version gates the auth verifier and the version-specific
# wire formats. Kept here in the leaf constants module (rather than oracle.tns)
# so oracle.cursor can import the 12.1 threshold without forming an import cycle
# — oracle.tns imports oracle.cursor.
FIELD_VERSION_11_2 = 6
FIELD_VERSION_12_1 = 7
FIELD_VERSION_12_2 = 8
FIELD_VERSION_12_2_EXT1 = 9
FIELD_VERSION_19_1 = 12
FIELD_VERSION_21_1 = 16
FIELD_VERSION_23_1 = 17

DictionaryType = Enum('DictionaryType', 'auth chgpwd close description dty exec fetch lobops login pig pro sess spfp start stop tran')

# OALL8 execute-option bit that turns on array-DML batch-error mode: a per-row
# error is collected (in the OER batch-error arrays) instead of aborting the
# batch. ORed into the leading Opt word (#18).
TNS_EXEC_OPTION_BATCH_ERRORS = 0x80000

# Value the 12c+ OALL8 al8i4 array carries at element index 9 when array-DML
# row counts are requested (oracledb arraydmlrowcounts). oracledb always sends
# 0x8000 there; with arraydmlrowcounts it sets 0xC000 (the extra 0x4000 bit).
# pyoracle's baseline is 0, so the whole 0xC000 is written when requested — the
# server's kpoal8Check rejects the al8pidmlrc pointer (below) as malformed
# (ORA-03137) without it. Reverse-engineered from an oracledb-thin capture (#18).
TNS_AL8I4_ARRAY_DML_ROWCOUNTS = 0xC000

TNS_LOB_OP_GET_LENGTH = 0x0001
TNS_LOB_OP_READ = 0x0002
TNS_LOB_OP_WRITE = 0x0040
TNS_LOB_OP_CREATE_TEMP = 0x0110

# Bind directions in the TTI_IOV response (one per bind, in bind order).
TNS_BIND_DIR_OUTPUT = 16
TNS_BIND_DIR_INPUT = 32
TNS_BIND_DIR_INPUT_OUTPUT = 48

ISO_LATIN_1_CHARSET = 31
UTF8_CHARSET = 871
AL32UTF8_CHARSET = 873
AL16UTF16_CHARSET = 2000

CharsetDict = {
    'we8iso8859p1' : 31,
    'ee8iso8859p2' : 32,
    'cl8iso8859p5' : 35,
    'ee8mswin1250' : 170,
    'cl8mswin1251' : 171,
    'we8mswin1252' : 178,
    'ja16euc' : 830,
    'zhs16gbk' : 852,
    'zht16big5' : 865,
    'zht16mswin950' : 867,
    'al32utf8' : 873,
    'al16utf16' : 2000
}

DEFAULT_HOST = ""
DEFAULT_PORT = 1521
DEFAULT_SID = ""

CONN_STATE_DISCONNECTED   = 0
CONN_STATE_CONNECTED      = 1
CONN_STATE_AUTH_NEGOTIATE = 2
CONN_STATE_AUTHENTICATED  = 3

MAX_SEQ_NUM = 127
