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
    TNS_TYPE_BDOUBLE, TNS_TYPE_BFLOAT, TNS_TYPE_CHAR,
    TNS_TYPE_DATE, TNS_TYPE_FLOAT, TNS_TYPE_LONG, TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER, TNS_TYPE_RAW, TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ, TNS_TYPE_VARCHAR, TNS_TYPE_VARNUM,
)

_BINARY_TYPES = (TNS_TYPE_RAW, TNS_TYPE_LONGRAW)
_TIMESTAMP_TYPES = (TNS_TYPE_DATE, TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ,
                    TNS_TYPE_TIMESTAMPLTZ)
_STRING_TYPES = (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR, TNS_TYPE_LONG)
_NUMBER_TYPES = (TNS_TYPE_NUMBER, TNS_TYPE_VARNUM)


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


def _explicit_type(type_code, precision, scale):
    # The exact Arrow type for a column whose decoded Python values are known to
    # match it, so pyarrow can skip type inference (#190). Inference is the cost
    # centre of build_table — it scans every value, and on a NUMBER-with-scale
    # (Decimal) column that is by far the slowest step. Returns None when no
    # safe fixed type can be derived (e.g. an unconstrained NUMBER, which
    # legitimately decodes to an int / Decimal mix, or a TZ / LOB / object
    # column), leaving that column to inference.
    if type_code in _NUMBER_TYPES:
        # Only a constrained NUMBER(p, s) has a fixed shape. precision 0 / scale
        # -127 is Oracle's "unconstrained" marker -> infer.
        if not precision or precision <= 0 or precision > 38:
            return None
        if scale and scale > 0:
            # Decimal values; decimal128 needs scale <= precision.
            return pa.decimal128(precision, scale) if scale <= precision else None
        if scale == 0:
            # Integer values; int64 holds up to 18 digits without overflow.
            return pa.int64() if precision <= 18 else None
        return None                                   # negative scale -> infer
    if type_code == TNS_TYPE_BFLOAT:
        return pa.float32()
    if type_code in (TNS_TYPE_BDOUBLE, TNS_TYPE_FLOAT):
        return pa.float64()
    if type_code in _STRING_TYPES:
        return pa.string()
    if type_code in _BINARY_TYPES:
        return pa.binary()
    # DATE / naive TIMESTAMP decode to naive datetimes; the TZ-aware variants
    # (TIMESTAMPTZ / LTZ) carry a tz, so leave those to inference.
    if type_code in (TNS_TYPE_DATE, TNS_TYPE_TIMESTAMP):
        return pa.timestamp("us")
    return None


def _column_array(values: list, type_code, scale, precision=None) -> pa.Array:
    # Build one Arrow column. Use the exact Oracle-derived type when one is safe
    # (skips pyarrow's per-value inference, #190); otherwise let pyarrow infer
    # from the values, falling back to the type map for an empty / all-NULL
    # column so the schema is still meaningful.
    Explicit = _explicit_type(type_code, precision, scale)
    if Explicit is not None:
        return pa.array(values, type=Explicit)
    if any(v is not None for v in values):
        return pa.array(values)
    return pa.array(values, type=_fallback_type(type_code, scale))


def build_table(rows: list, description: list) -> pa.Table:
    """Build a pyarrow.Table from buffered rows + a PEP 249 description (#162).

    `rows` is a list of per-row sequences (column-major is derived here);
    `description` supplies the column names (index 0), type codes (1),
    precision (4) and scale (5)."""
    Names = [Col[0] for Col in description]
    NumCols = len(Names)
    # Transpose row-major rows into per-column value lists.
    Columns: list[list] = [[] for _ in range(NumCols)]
    for Row in rows:
        for I in range(NumCols):
            Columns[I].append(Row[I] if I < len(Row) else None)
    Arrays = [_column_array(Columns[I], description[I][1], description[I][5],
                            description[I][4])
              for I in range(NumCols)]
    return pa.table(dict(zip(Names, Arrays))) if Names else pa.table({})
