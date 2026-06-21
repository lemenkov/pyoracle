# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Arrow / DataFrame bulk fetch (#162). cursor.fetch_df_all() and
# cursor.fetch_df_batches() return query results as a pyarrow.Table (column
# major) instead of per-row tuples, for fast hand-off to pandas / Polars /
# pyarrow. The rows come from the ordinary fetch buffer; this module just
# reshapes them column-major and maps Oracle types to Arrow.

from __future__ import annotations

import pyarrow as pa

from oracle.tns_consts import (
    TNS_TYPE_BDOUBLE, TNS_TYPE_BFLOAT, TNS_TYPE_CHAR, TNS_TYPE_CLOB,
    TNS_TYPE_DATE, TNS_TYPE_FLOAT, TNS_TYPE_LONG, TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER, TNS_TYPE_RAW, TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ, TNS_TYPE_VARCHAR, TNS_TYPE_VARNUM,
)

# Oracle TNS type -> Arrow type, used only to give an empty / all-NULL column a
# meaningful schema. A column that has at least one value is built by pyarrow's
# own inference, which handles the int / Decimal / float mix Oracle NUMBER
# decodes into (and yields decimal128 / int64 / double as appropriate).
_STRING_TYPES = (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_LONG, TNS_TYPE_CLOB)
_BINARY_TYPES = (TNS_TYPE_RAW, TNS_TYPE_LONGRAW)
_TIMESTAMP_TYPES = (TNS_TYPE_DATE, TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ,
                    TNS_TYPE_TIMESTAMPLTZ)


def _fallback_type(type_code, scale) -> pa.DataType:
    if type_code in (TNS_TYPE_NUMBER, TNS_TYPE_VARNUM):
        # scale 0 -> integer column; anything else -> floating point.
        return pa.int64() if scale in (0, None) else pa.float64()
    if type_code == TNS_TYPE_BFLOAT:
        return pa.float32()
    if type_code in (TNS_TYPE_BDOUBLE, TNS_TYPE_FLOAT):
        return pa.float64()
    if type_code in _TIMESTAMP_TYPES:
        return pa.timestamp("us")
    if type_code in _BINARY_TYPES:
        return pa.binary()
    return pa.string()


def _column_array(values: list, type_code, scale) -> pa.Array:
    # Build one Arrow column. Let pyarrow infer the type from the values when
    # there is at least one non-NULL; fall back to the Oracle-type mapping for
    # an empty or all-NULL column so the schema is still meaningful.
    if any(v is not None for v in values):
        return pa.array(values)
    return pa.array(values, type=_fallback_type(type_code, scale))


def build_table(rows: list, description: list) -> pa.Table:
    """Build a pyarrow.Table from buffered rows + a PEP 249 description (#162).

    `rows` is a list of per-row sequences (column-major is derived here);
    `description` supplies the column names (index 0), type codes (1) and
    scale (5)."""
    Names = [Col[0] for Col in description]
    NumCols = len(Names)
    # Transpose row-major rows into per-column value lists.
    Columns: list[list] = [[] for _ in range(NumCols)]
    for Row in rows:
        for I in range(NumCols):
            Columns[I].append(Row[I] if I < len(Row) else None)
    Arrays = [_column_array(Columns[I], description[I][1], description[I][5])
              for I in range(NumCols)]
    return pa.table(dict(zip(Names, Arrays))) if Names else pa.table({})
