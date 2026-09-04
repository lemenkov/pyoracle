# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Public value/marker types for binds and fetches that have no faithful stdlib
# equivalent. Kept in their own low-level module (stdlib-only imports) so both
# the encoder (`tns.py`) and the decoders (`types.py`) can import them without a
# circular dependency.

import datetime
from decimal import Decimal

from seerdb.common.tns_consts import (
    TNS_TYPE_BDOUBLE,
    TNS_TYPE_BFLOAT,
    TNS_TYPE_BLOB,
    TNS_TYPE_BOOLEAN,
    TNS_TYPE_CHAR,
    TNS_TYPE_CLOB,
    TNS_TYPE_DATE,
    TNS_TYPE_INTERVALDS,
    TNS_TYPE_INTERVALYM,
    TNS_TYPE_JSON,
    TNS_TYPE_LONG,
    TNS_TYPE_LONGRAW,
    TNS_TYPE_NUMBER,
    TNS_TYPE_RAW,
    TNS_TYPE_REFCURSOR,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ,
    TNS_TYPE_TIMESTAMPTZ,
    TNS_TYPE_UROWID,
    TNS_TYPE_VARCHAR,
    TNS_TYPE_VECTOR,
)

# ROWID is reported by the DCB describe with wire type code 11 (TNS_TYPE_ROWID
# = 104 is Oracle's other, bind-side rowid code). Keep a local name for the
# fetch code so the description map below is unambiguous.
TNS_TYPE_ROWID_FETCH = 11


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
# Fetch-oriented types (mostly appear in cursor.description; kept as objects so
# description[i][1] is the same seerdb.DB_TYPE_* constant, matching oracledb).
# tns_type is the wire code the DCB reports for a column of that type.
DB_TYPE_CHAR = _DbType('DB_TYPE_CHAR', TNS_TYPE_CHAR, 2000)
DB_TYPE_LONG = _DbType('DB_TYPE_LONG', TNS_TYPE_LONG, 32767)
DB_TYPE_LONG_RAW = _DbType('DB_TYPE_LONG_RAW', TNS_TYPE_LONGRAW, 32767)
DB_TYPE_ROWID = _DbType('DB_TYPE_ROWID', TNS_TYPE_ROWID_FETCH, 18)
DB_TYPE_UROWID = _DbType('DB_TYPE_UROWID', TNS_TYPE_UROWID, 5267)
DB_TYPE_CLOB = _DbType('DB_TYPE_CLOB', TNS_TYPE_CLOB, 32767)
DB_TYPE_NCLOB = _DbType('DB_TYPE_NCLOB', TNS_TYPE_CLOB, 32767, csfrm=2)
DB_TYPE_BLOB = _DbType('DB_TYPE_BLOB', TNS_TYPE_BLOB, 32767)
DB_TYPE_TIMESTAMP_LTZ = _DbType('DB_TYPE_TIMESTAMP_LTZ', TNS_TYPE_TIMESTAMPLTZ, 11)
DB_TYPE_JSON = _DbType('DB_TYPE_JSON', TNS_TYPE_JSON, 32767)
DB_TYPE_BOOLEAN = _DbType('DB_TYPE_BOOLEAN', TNS_TYPE_BOOLEAN, 4)
DB_TYPE_VECTOR = _DbType('DB_TYPE_VECTOR', TNS_TYPE_VECTOR, 32767)

# The rest of the type objects PEP 249 requires a module to expose, alongside
# STRING and NUMBER above. Each is an alias for the DbType the server reports for
# that kind of column, which is the same convention STRING and NUMBER already
# follow — so they double as `cursor.var()` type specs.
#
# One consequence worth stating: each matches a single wire type, so comparing
# `cursor.description[i][1] == STRING` is true for VARCHAR but not for CHAR or
# CLOB. PEP 249 allows a type object to match a whole family; broadening these
# would change what the existing STRING and NUMBER compare equal to, so it is a
# separate decision rather than part of adding the missing names.
BINARY = DB_TYPE_RAW
ROWID = DB_TYPE_ROWID
# Oracle's DATE carries a time component, so it — not TIMESTAMP — is the type a
# plain date/time column reports.
DATETIME = DB_TYPE_DATE


# The constructors PEP 249 requires. A caller that has a date, a time or a byte
# string already can bind it directly; these exist so code written against the
# DB-API generically, without knowing which driver is underneath, works here too.
def Date(year: int, month: int, day: int) -> datetime.date:  # noqa: N802
    """A value holding a date (PEP 249)."""
    return datetime.date(year, month, day)


def Time(hour: int, minute: int, second: int) -> datetime.time:  # noqa: N802
    """A value holding a time of day (PEP 249)."""
    return datetime.time(hour, minute, second)


def Timestamp(  # noqa: N802
    year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0
) -> datetime.datetime:
    """A value holding a date and time (PEP 249)."""
    return datetime.datetime(year, month, day, hour, minute, second)


def DateFromTicks(ticks: float) -> datetime.date:  # noqa: N802
    """A date from a Unix timestamp, in local time (PEP 249)."""
    return datetime.date.fromtimestamp(ticks)


def TimeFromTicks(ticks: float) -> datetime.time:  # noqa: N802
    """A time of day from a Unix timestamp, in local time (PEP 249)."""
    return datetime.datetime.fromtimestamp(ticks).time()


def TimestampFromTicks(ticks: float) -> datetime.datetime:  # noqa: N802
    """A date and time from a Unix timestamp, in local time (PEP 249)."""
    return datetime.datetime.fromtimestamp(ticks)


def Binary(value) -> bytes:  # noqa: N802
    """A value holding binary data (PEP 249).

    Accepts what a caller is likely to already have — bytes, a bytearray or a
    memoryview pass through as bytes; a str is encoded UTF-8, which is what
    binding one to a RAW column would do anyway.
    """
    if isinstance(value, str):
        return value.encode('utf-8')
    return bytes(value)


# Map the (wire type code, charset form) the server reports for a fetched column
# (DCB data_type + csfrm) to its DbType. Keyed on the actual fetch codes so
# cursor.description[i][1] is the seerdb.DB_TYPE_* object (oracledb parity). The
# csfrm split distinguishes national types (VARCHAR/NVARCHAR, CHAR/NCHAR,
# CLOB/NCLOB) that share a wire code.
_FETCH_DBTYPE: dict[tuple[int, int], _DbType] = {
    (TNS_TYPE_NUMBER, 1): DB_TYPE_NUMBER,
    (TNS_TYPE_VARCHAR, 1): DB_TYPE_VARCHAR,
    (TNS_TYPE_VARCHAR, 2): DB_TYPE_NVARCHAR,
    (TNS_TYPE_CHAR, 1): DB_TYPE_CHAR,
    (TNS_TYPE_CHAR, 2): DB_TYPE_NCHAR,
    (TNS_TYPE_RAW, 1): DB_TYPE_RAW,
    (TNS_TYPE_DATE, 1): DB_TYPE_DATE,
    (TNS_TYPE_LONG, 1): DB_TYPE_LONG,
    (TNS_TYPE_LONGRAW, 1): DB_TYPE_LONG_RAW,
    (TNS_TYPE_ROWID_FETCH, 1): DB_TYPE_ROWID,
    (TNS_TYPE_UROWID, 1): DB_TYPE_UROWID,
    (TNS_TYPE_CLOB, 1): DB_TYPE_CLOB,
    (TNS_TYPE_CLOB, 2): DB_TYPE_NCLOB,
    (TNS_TYPE_BLOB, 1): DB_TYPE_BLOB,
    (TNS_TYPE_BFLOAT, 1): DB_TYPE_BINARY_FLOAT,
    (TNS_TYPE_BDOUBLE, 1): DB_TYPE_BINARY_DOUBLE,
    (TNS_TYPE_TIMESTAMP, 1): DB_TYPE_TIMESTAMP,
    (TNS_TYPE_TIMESTAMPTZ, 1): DB_TYPE_TIMESTAMP_TZ,
    (TNS_TYPE_TIMESTAMPLTZ, 1): DB_TYPE_TIMESTAMP_LTZ,
    (TNS_TYPE_INTERVALYM, 1): DB_TYPE_INTERVAL_YM,
    (TNS_TYPE_INTERVALDS, 1): DB_TYPE_INTERVAL_DS,
    (TNS_TYPE_REFCURSOR, 1): DB_TYPE_CURSOR,
    (TNS_TYPE_JSON, 1): DB_TYPE_JSON,
    (TNS_TYPE_BOOLEAN, 1): DB_TYPE_BOOLEAN,
    (TNS_TYPE_VECTOR, 1): DB_TYPE_VECTOR,
}


def dbtype_for_oracle_type(tns_type: int, csfrm: int) -> _DbType | None:
    # Resolve a fetched column's DbType. Fall back to the non-national (csfrm 1)
    # entry when the server reports csfrm 0 for a non-char type.
    return _FETCH_DBTYPE.get((tns_type, csfrm or 1)) or _FETCH_DBTYPE.get((tns_type, 1))


# Wire type codes whose cursor.description display_size follows oracledb's
# special rules: 23 for the DATE/TIMESTAMP family, a computed width for the
# NUMBER family (NUMBER, BINARY_FLOAT, BINARY_DOUBLE).
_DATE_TNS_TYPES = frozenset(
    {TNS_TYPE_DATE, TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ, TNS_TYPE_TIMESTAMPLTZ}
)
_NUMBER_TNS_TYPES = frozenset({TNS_TYPE_NUMBER, TNS_TYPE_BFLOAT, TNS_TYPE_BDOUBLE})

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


class RefCursorBind:
    """Base marker for a REF CURSOR bind sentinel.

    The encoder in ``seerdb.common.tns`` emits a REFCURSOR bind when a bind
    value is an instance of this. It lives here in the leaf marker module (not
    in the client) so the codec can recognise the sentinel without importing
    anything from ``seerdb.client`` — keeping ``common`` a self-contained leaf
    that both the client and the Mirror server build on. The client's public
    ``cursor`` sentinel subclasses it.
    """
