# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Public value/marker types for binds and fetches that have no faithful stdlib
# equivalent. Kept in their own low-level module (stdlib-only imports) so both
# the encoder (`tns.py`) and the decoders (`types.py`) can import them without a
# circular dependency.

import datetime
from decimal import Decimal

from seerdb.tns_consts import (
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_CHAR,
    TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_REFCURSOR,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_VARCHAR,
)


class TempLob:
    """A bind marker for a server-side temporary LOB (#91).

    Large CLOB / BLOB values (> 32767 bytes) cannot be bound into a PL/SQL
    locator parameter through the regular streamed path — the server rejects
    them with ORA-01460. The driver instead allocates a temp LOB
    (TTI_LOBOPS CREATE_TEMP), streams the value into it (WRITE) and binds this
    marker, which carries the resulting locator. The bind encoder emits a
    CLOB / BLOB OAC plus the LOB-descriptor value (`01 28 28` + ub2 length +
    locator), the same descriptor framing the native VECTOR / JSON binds use.

    `oac_size` is the byte budget announced in the OAC (CLOB = chars * 4 for
    AL32UTF8, BLOB = byte length), matching python-oracledb.
    """

    __slots__ = ('locator', 'is_blob', 'oac_size')

    def __init__(self, locator: bytes, is_blob: bool, oac_size: int):
        self.locator = locator
        self.is_blob = is_blob
        self.oac_size = oac_size

    def __repr__(self) -> str:
        kind = 'BLOB' if self.is_blob else 'CLOB'
        return f'TempLob({kind}, {len(self.locator)}B locator)'


class _DbType:
    """An Oracle bind type usable as a `cursor.var()` / OUT-bind type spec."""

    __slots__ = ('name', 'tns_type', 'default_size', 'csfrm')

    def __init__(self, name: str, tns_type: int, default_size: int, csfrm: int = 1):
        self.name = name
        self.tns_type = tns_type
        self.default_size = default_size
        # Character-set form: 1 = database charset (default), 2 = national
        # charset (NCHAR / NVARCHAR2 → AL16UTF16). #174.
        self.csfrm = csfrm

    def __repr__(self) -> str:
        return self.name


# oracledb-compatible type-constant aliases for cursor.var() / OUT binds.
# The default sizes are the fixed wire widths the server reserves for each
# scalar OUT value (matching the value-sized OAC in tns.encode_token_oac).
DB_TYPE_NUMBER = NUMBER = _DbType('DB_TYPE_NUMBER', TNS_TYPE_NUMBER, 22)
DB_TYPE_VARCHAR = STRING = _DbType('DB_TYPE_VARCHAR', TNS_TYPE_VARCHAR, 32767)
# National-charset string types (#174): csfrm 2 → AL16UTF16. Bind a str through
# cursor.var(seerdb.DB_TYPE_NVARCHAR) / DB_TYPE_NCHAR to target an NVARCHAR2 /
# NCHAR column. Needed on 9i (a non-Unicode DB charset can't store all of
# Unicode, but the national charset can); harmless on 10g+.
DB_TYPE_NVARCHAR = _DbType('DB_TYPE_NVARCHAR', TNS_TYPE_VARCHAR, 32767, csfrm=2)
DB_TYPE_NCHAR = _DbType('DB_TYPE_NCHAR', TNS_TYPE_CHAR, 32767, csfrm=2)
DB_TYPE_RAW = _DbType('DB_TYPE_RAW', TNS_TYPE_RAW, 32767)
DB_TYPE_DATE = _DbType('DB_TYPE_DATE', TNS_TYPE_DATE, 7)
DB_TYPE_CURSOR = CURSOR = _DbType('DB_TYPE_CURSOR', TNS_TYPE_REFCURSOR, 1)
DB_TYPE_TIMESTAMP = _DbType('DB_TYPE_TIMESTAMP', TNS_TYPE_TIMESTAMP, 11)
DB_TYPE_TIMESTAMP_TZ = _DbType('DB_TYPE_TIMESTAMP_TZ', TNS_TYPE_TIMESTAMPTZ, 13)
DB_TYPE_BINARY_FLOAT = _DbType('DB_TYPE_BINARY_FLOAT', TNS_TYPE_BFLOAT, 4)
DB_TYPE_BINARY_DOUBLE = _DbType('DB_TYPE_BINARY_DOUBLE', TNS_TYPE_BDOUBLE, 8)
DB_TYPE_INTERVAL_DS = _DbType('DB_TYPE_INTERVAL_DS', TNS_TYPE_INTERVALDS, 11)
DB_TYPE_INTERVAL_YM = _DbType('DB_TYPE_INTERVAL_YM', TNS_TYPE_INTERVALYM, 5)

_PYTYPE_TO_DBTYPE = {
    int: NUMBER,
    float: NUMBER,
    Decimal: NUMBER,
    str: STRING,
    bytes: DB_TYPE_RAW,
    bytearray: DB_TYPE_RAW,
    datetime.date: DB_TYPE_DATE,
    datetime.datetime: DB_TYPE_DATE,
    datetime.timedelta: DB_TYPE_INTERVAL_DS,
}


def _resolve_dbtype(typ: object) -> _DbType:
    if isinstance(typ, _DbType):
        return typ
    if isinstance(typ, type) and typ in _PYTYPE_TO_DBTYPE:
        return _PYTYPE_TO_DBTYPE[typ]
    raise ValueError(f'unsupported var() type: {typ!r}')


class Var:
    """A bind container that can receive an OUT / IN OUT value.

    Create via `cursor.var(typ, size=None)`, where `typ` is a Python type
    (`int`, `str`, `bytes`, `datetime`, ...) or an `seerdb.*` type constant.
    Pass it in a `callproc` / `execute` parameter list for an OUT or IN OUT
    argument; seed an IN OUT value with `setvalue(0, value)` and read the
    result afterwards with `getvalue()`.
    """

    __slots__ = ('dbtype', 'size', '_value', 'has_value', 'is_array', 'num_elements')

    def __init__(
        self,
        typ: object,
        size: int | None = None,
        is_array: bool = False,
        num_elements: int = 0,
    ):
        self.dbtype = _resolve_dbtype(typ)
        self.size = size if size is not None else self.dbtype.default_size
        self._value: object = [] if is_array else None
        self.has_value = False
        # PL/SQL associative-array (index-by table) bind (#122): is_array marks
        # the bulk-array form; num_elements is the declared maximum capacity.
        self.is_array = is_array
        self.num_elements = num_elements

    def setvalue(self, pos: int, value: object) -> None:
        self._value = value
        self.has_value = True

    def getvalue(self, pos: int = 0) -> object:
        return self._value

    def __repr__(self) -> str:
        if self.is_array:
            return f'Var({self.dbtype}[{self.num_elements}], value={self._value!r})'
        return f'Var({self.dbtype}, size={self.size}, value={self._value!r})'


class BinaryFloat(float):
    """Bind marker: send the value as a native BINARY_FLOAT (32-bit IEEE-754)
    rather than the default NUMBER. A plain ``float`` still binds as NUMBER for
    backwards compatibility; wrap it in ``BinaryFloat`` to force the single-
    precision binary type (e.g. to round-trip ``inf`` / ``nan`` exactly).

    It is a ``float`` subclass, so it behaves like one in arithmetic and
    ``isinstance(x, float)`` checks.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f'BinaryFloat({float.__repr__(self)})'


class BinaryDouble(float):
    """Bind marker: send the value as a native BINARY_DOUBLE (64-bit IEEE-754)
    rather than the default NUMBER. See :class:`BinaryFloat`.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f'BinaryDouble({float.__repr__(self)})'


class IntervalYM:
    """An Oracle ``INTERVAL YEAR TO MONTH`` value.

    There is no stdlib type for a calendar interval (a month is not a fixed
    number of days), so this small class carries the two fields. It is used both
    as the decoded result of an interval-year-to-month column and as a bind
    input. Years and months are normalised on construction so that
    ``abs(months) < 12`` and both fields share the interval's sign, matching how
    the server stores and returns the value.
    """

    __slots__ = ('years', 'months')

    def __init__(self, years: int = 0, months: int = 0):
        total = int(years) * 12 + int(months)
        sign = -1 if total < 0 else 1
        total = abs(total)
        self.years = sign * (total // 12)
        self.months = sign * (total % 12)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IntervalYM):
            return NotImplemented
        return self.years == other.years and self.months == other.months

    def __hash__(self) -> int:
        return hash((self.years, self.months))

    def __repr__(self) -> str:
        return f'IntervalYM(years={self.years}, months={self.months})'


# IntervalYM is defined above, so register its Python-type mapping now that the
# class exists (lets `cursor.var(seerdb.IntervalYM)` resolve).
_PYTYPE_TO_DBTYPE[IntervalYM] = DB_TYPE_INTERVAL_YM


class JSON:
    """Bind marker: send the wrapped Python value into a native ``JSON`` column
    (21c+). A bare ``dict`` already binds as JSON automatically; wrap a
    ``list`` / ``str`` / number / ``bool`` / ``None`` in ``JSON`` to bind *it*
    as JSON too (a bare list otherwise means a VECTOR, and bare scalars bind as
    their native SQL types). The value must be JSON-serialisable.

    seerdb serialises the value to JSON text and binds it as a string; the
    server casts it to the column's JSON type (see docs/PROTOCOL.md §17.2).
    """

    __slots__ = ('value',)

    def __init__(self, value: object):
        self.value = value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, JSON):
            return NotImplemented
        return self.value == other.value

    def __repr__(self) -> str:
        return f'JSON({self.value!r})'
