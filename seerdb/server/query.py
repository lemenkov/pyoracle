# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Server-side query path — parse the client's OALL8 execute (11g).

The inverse of ``tns.encode_dictionary_exec`` for the 11g wire shape: an
``OALL8`` (TTI_ALL8) function message whose fixed header carries the SQL length
and option/bind counts, followed by the raw SQL text. The describe / row
encoders that answer it are layered on separately.
"""

from __future__ import annotations

from seerdb.common.tns import (
    _CREATE_TEMP_PREFIX as _CREATE_TEMP_PREFIX,
)
from seerdb.common.tns import (
    _EXEC_OPTION_BATCH_ERRORS as _EXEC_OPTION_BATCH_ERRORS,
)
from seerdb.common.tns import (
    _EXEC_OPTION_COMMIT as _EXEC_OPTION_COMMIT,
)
from seerdb.common.tns import (
    _LOBOPS_ACK_OPS as _LOBOPS_ACK_OPS,
)
from seerdb.common.tns import (
    _MARKER_LEN as _MARKER_LEN,
)
from seerdb.common.tns import (
    _OCI_ALL8_CURSOR_OFF as _OCI_ALL8_CURSOR_OFF,
)
from seerdb.common.tns import (
    _OCI_ALL8_SQL_OFF as _OCI_ALL8_SQL_OFF,
)
from seerdb.common.tns import (
    _OCI_ALL8_SQLLEN3_OFF as _OCI_ALL8_SQLLEN3_OFF,
)
from seerdb.common.tns import (
    _OCI_BIND_COUNT_OFF as _OCI_BIND_COUNT_OFF,
)
from seerdb.common.tns import (
    _OCI_BIND_TYPES as _OCI_BIND_TYPES,
)
from seerdb.common.tns import (
    _OCI_CHAR_TYPES as _OCI_CHAR_TYPES,
)
from seerdb.common.tns import (
    _OCI_CMD_TYPE_OFF as _OCI_CMD_TYPE_OFF,
)
from seerdb.common.tns import (
    _OCI_DCB_CHAR_FLAG as _OCI_DCB_CHAR_FLAG,
)
from seerdb.common.tns import (
    _OCI_DCB_COL_POSTNAME as _OCI_DCB_COL_POSTNAME,
)
from seerdb.common.tns import (
    _OCI_DCB_COL_PRENAME as _OCI_DCB_COL_PRENAME,
)
from seerdb.common.tns import (
    _OCI_DCB_DATE_LEN as _OCI_DCB_DATE_LEN,
)
from seerdb.common.tns import (
    _OCI_DCB_MARKER_OFF as _OCI_DCB_MARKER_OFF,
)
from seerdb.common.tns import (
    _OCI_DCB_NUMCOLS_OFF as _OCI_DCB_NUMCOLS_OFF,
)
from seerdb.common.tns import (
    _OCI_DCB_PREAMBLE_LEN as _OCI_DCB_PREAMBLE_LEN,
)
from seerdb.common.tns import (
    _OCI_DCB_TAIL_LEN as _OCI_DCB_TAIL_LEN,
)
from seerdb.common.tns import (
    _OCI_DDL_COMMAND_TYPE as _OCI_DDL_COMMAND_TYPE,
)
from seerdb.common.tns import (
    _OCI_DDL_VERB_COMMAND_TYPE as _OCI_DDL_VERB_COMMAND_TYPE,
)
from seerdb.common.tns import (
    _OCI_DDL_VERB_DEFAULT_OBJECT as _OCI_DDL_VERB_DEFAULT_OBJECT,
)
from seerdb.common.tns import (
    _OCI_DML_CMD as _OCI_DML_CMD,
)
from seerdb.common.tns import (
    _OCI_DML_ROWCOUNT_OFF as _OCI_DML_ROWCOUNT_OFF,
)
from seerdb.common.tns import (
    _OCI_EXEC_OER_OFF as _OCI_EXEC_OER_OFF,
)
from seerdb.common.tns import (
    _OCI_LOB_CHUNK as _OCI_LOB_CHUNK,
)
from seerdb.common.tns import (
    _OCI_LOB_FETCH_STATUS as _OCI_LOB_FETCH_STATUS,
)
from seerdb.common.tns import (
    _OCI_LOB_ROW_SIZE_OFF as _OCI_LOB_ROW_SIZE_OFF,
)
from seerdb.common.tns import (
    _OCI_LOB_RXH_NONZERO as _OCI_LOB_RXH_NONZERO,
)
from seerdb.common.tns import (
    _OCI_LOB_TAIL_AMOUNT_OFF as _OCI_LOB_TAIL_AMOUNT_OFF,
)
from seerdb.common.tns import (
    _OCI_LOB_TAIL_SIZE_OFF as _OCI_LOB_TAIL_SIZE_OFF,
)
from seerdb.common.tns import (
    _OCI_LOB_TYPES as _OCI_LOB_TYPES,
)
from seerdb.common.tns import (
    _OCI_LOBOPS_AMOUNT_OFF as _OCI_LOBOPS_AMOUNT_OFF,
)
from seerdb.common.tns import (
    _OCI_LOBOPS_OFFSET_OFF as _OCI_LOBOPS_OFFSET_OFF,
)
from seerdb.common.tns import (
    _OCI_LONG_CHUNK as _OCI_LONG_CHUNK,
)
from seerdb.common.tns import (
    _OCI_LONG_TRAILER as _OCI_LONG_TRAILER,
)
from seerdb.common.tns import (
    _OCI_LONG_TYPES as _OCI_LONG_TYPES,
)
from seerdb.common.tns import (
    _OCI_MORE_ROWS_FLAG as _OCI_MORE_ROWS_FLAG,
)
from seerdb.common.tns import (
    _OCI_MORE_ROWS_OFF as _OCI_MORE_ROWS_OFF,
)
from seerdb.common.tns import (
    _OCI_OAC_MARKER as _OCI_OAC_MARKER,
)
from seerdb.common.tns import (
    _OCI_OUTBIND_BINDCOUNT_OFF as _OCI_OUTBIND_BINDCOUNT_OFF,
)
from seerdb.common.tns import (
    _OCI_OUTBIND_DEFINE_MARKER as _OCI_OUTBIND_DEFINE_MARKER,
)
from seerdb.common.tns import (
    _OCI_OUTBIND_RETCODE as _OCI_OUTBIND_RETCODE,
)
from seerdb.common.tns import (
    _OCI_ROW_STATUS_LEN as _OCI_ROW_STATUS_LEN,
)
from seerdb.common.tns import (
    _OCI_RXH_LEN as _OCI_RXH_LEN,
)
from seerdb.common.tns import (
    _OCI_RXH_NONZERO as _OCI_RXH_NONZERO,
)
from seerdb.common.tns import (
    _OCI_UNSIZED_TYPES as _OCI_UNSIZED_TYPES,
)
from seerdb.common.tns import (
    _SERVER_VERSION_SLOT as _SERVER_VERSION_SLOT,
)
from seerdb.common.tns import (
    _TEMP_LOB_BIND_PREFIX as _TEMP_LOB_BIND_PREFIX,
)
from seerdb.common.tns import (
    _TEMP_LOB_LOCATOR_PREFIX as _TEMP_LOB_LOCATOR_PREFIX,
)

# Re-exports: codec primitives now defined in common/tns, kept importable from
# the Mirror server API (seerdb.server.query) for existing call sites.
from seerdb.common.tns import (  # noqa: E402,F401
    ColumnMeta as ColumnMeta,
)
from seerdb.common.tns import (
    ExecRequest as ExecRequest,
)
from seerdb.common.tns import (
    FetchRequest as FetchRequest,
)
from seerdb.common.tns import (
    LobOpsRequest as LobOpsRequest,
)
from seerdb.common.tns import (
    RefCursorOutBind as RefCursorOutBind,
)
from seerdb.common.tns import (
    ScalarOutBind as ScalarOutBind,
)
from seerdb.common.tns import (
    TempLobRef as TempLobRef,
)
from seerdb.common.tns import (
    _decode_bind_value as _decode_bind_value,
)
from seerdb.common.tns import (
    _decode_describe_oci as _decode_describe_oci,
)
from seerdb.common.tns import (
    _decode_lobops_chunked as _decode_lobops_chunked,
)
from seerdb.common.tns import (
    _encode_dcb_column_oci as _encode_dcb_column_oci,
)
from seerdb.common.tns import (
    _encode_oci_value as _encode_oci_value,
)
from seerdb.common.tns import (
    _encode_refcursor_out as _encode_refcursor_out,
)
from seerdb.common.tns import (
    _lobops_locator_after_operation as _lobops_locator_after_operation,
)
from seerdb.common.tns import (
    _oci_dcb_tail as _oci_dcb_tail,
)
from seerdb.common.tns import (
    _oci_lob_byte_size as _oci_lob_byte_size,
)
from seerdb.common.tns import (
    _oci_lob_data as _oci_lob_data,
)
from seerdb.common.tns import (
    _oci_lob_rxh as _oci_lob_rxh,
)
from seerdb.common.tns import (
    _oci_row_status as _oci_row_status,
)
from seerdb.common.tns import (
    _oci_rxh as _oci_rxh,
)
from seerdb.common.tns import (
    _oci_ub4 as _oci_ub4,
)
from seerdb.common.tns import (
    _parse_oci_binds as _parse_oci_binds,
)
from seerdb.common.tns import (
    _read_bind_value as _read_bind_value,
)
from seerdb.common.tns import (
    _read_chunked_sql as _read_chunked_sql,
)
from seerdb.common.tns import (
    _scroll_terminator as _scroll_terminator,
)
from seerdb.common.tns import (
    ddl_command_type as ddl_command_type,
)
from seerdb.common.tns import (
    encode_batch_errors_status as encode_batch_errors_status,
)
from seerdb.common.tns import (
    encode_commit_status_oci as encode_commit_status_oci,
)
from seerdb.common.tns import (
    encode_create_temp_response as encode_create_temp_response,
)
from seerdb.common.tns import (
    encode_ddl_status_oci as encode_ddl_status_oci,
)
from seerdb.common.tns import (
    encode_describe as encode_describe,
)
from seerdb.common.tns import (
    encode_describe_oci as encode_describe_oci,
)
from seerdb.common.tns import (
    encode_dml_status_oci as encode_dml_status_oci,
)
from seerdb.common.tns import (
    encode_error as encode_error,
)
from seerdb.common.tns import (
    encode_error_oci as encode_error_oci,
)
from seerdb.common.tns import (
    encode_fetch_batch_oci as encode_fetch_batch_oci,
)
from seerdb.common.tns import (
    encode_fetch_terminator_oci as encode_fetch_terminator_oci,
)
from seerdb.common.tns import (
    encode_lob_describe_oci as encode_lob_describe_oci,
)
from seerdb.common.tns import (
    encode_lob_fetch_rows_oci as encode_lob_fetch_rows_oci,
)
from seerdb.common.tns import (
    encode_lob_locator_oci as encode_lob_locator_oci,
)
from seerdb.common.tns import (
    encode_lob_read_response_oci as encode_lob_read_response_oci,
)
from seerdb.common.tns import (
    encode_lob_read_response_thin as encode_lob_read_response_thin,
)
from seerdb.common.tns import (
    encode_lobops_ack as encode_lobops_ack,
)
from seerdb.common.tns import (
    encode_logoff_status_oci as encode_logoff_status_oci,
)
from seerdb.common.tns import (
    encode_long_fetch_row_oci as encode_long_fetch_row_oci,
)
from seerdb.common.tns import (
    encode_long_value_oci as encode_long_value_oci,
)
from seerdb.common.tns import (
    encode_more_rows as encode_more_rows,
)
from seerdb.common.tns import (
    encode_oci_oer as encode_oci_oer,
)
from seerdb.common.tns import (
    encode_out_bind_response_oci as encode_out_bind_response_oci,
)
from seerdb.common.tns import (
    encode_out_bind_response_thin as encode_out_bind_response_thin,
)
from seerdb.common.tns import (
    encode_query_response_oci as encode_query_response_oci,
)
from seerdb.common.tns import (
    encode_reexec_row_oci as encode_reexec_row_oci,
)
from seerdb.common.tns import (
    encode_rows as encode_rows,
)
from seerdb.common.tns import (
    encode_scroll_open_response as encode_scroll_open_response,
)
from seerdb.common.tns import (
    encode_scroll_response as encode_scroll_response,
)
from seerdb.common.tns import (
    encode_status as encode_status,
)
from seerdb.common.tns import (
    encode_status_oci as encode_status_oci,
)
from seerdb.common.tns import (
    encode_version_banner_oci as encode_version_banner_oci,
)
from seerdb.common.tns import (
    is_reexecute_oci as is_reexecute_oci,
)
from seerdb.common.tns import (
    is_version_call_oci as is_version_call_oci,
)
from seerdb.common.tns import (
    mint_temp_lob_locator as mint_temp_lob_locator,
)
from seerdb.common.tns import (
    oci_lob_contents as oci_lob_contents,
)
from seerdb.common.tns import (
    parse_exec as parse_exec,
)
from seerdb.common.tns import (
    parse_exec_oci as parse_exec_oci,
)
from seerdb.common.tns import (
    parse_fetch as parse_fetch,
)
from seerdb.common.tns import (
    parse_lobops_read as parse_lobops_read,
)
from seerdb.common.tns import (
    parse_lobops_request as parse_lobops_request,
)
from seerdb.common.tns import (
    peek_exec_cursor as peek_exec_cursor,
)
from seerdb.common.tns import (
    scroll_start_row as scroll_start_row,
)
from seerdb.common.tns import (
    strip_oci_piggyback as strip_oci_piggyback,
)


# The very first thing sqlplus / thick OCI sends after login is a version call
# (its TTC payload leads with 0x11 0x6b); the server answers with its banner, and
# sqlplus prints "Connected to: <banner>". The reply is a TTI_RPA carrying the
# banner as a DALC (ub2 count + ub1-chunked string) plus a fixed 10-byte packed
# version/flags trailer (#265).


# --- Thin (seerdb / oracledb-thin) LOB read (#413) ---
# The thin client keeps the RXD LOB locator opaque and hands it straight back in a
# TTI_LOBOPS READ (it asks for the whole LOB at once — amount 0x40000000 — so no
# read loop). The Mirror therefore mints a fixed placeholder locator and answers
# the reads from a row-major queue in order, matching the locators the row emits.
# The RXD block is `ub4 num_bytes | DALC(locator)` (a NULL LOB is a lone 0x00).


# --- Temp-LOB WRITE flow (the Mirror's server side, #412) --------------------
#
# A programmatic client writing a LOB too large for an inline bind does
# CREATE_TEMP (allocate a temp LOB) -> WRITE (stream bytes into it) -> bind the
# temp locator on execute. The Mirror mints a locator, accumulates the WRITE
# bytes, and resolves the bound locator to those bytes for the backend. The
# request layout mirrors docs/PROTOCOL.md §14.1/§14.2 (the client encoders in
# seerdb/common/tns.py); this is the inverse.
