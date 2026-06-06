# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Public value/marker types for binds and fetches that have no faithful stdlib
# equivalent. Kept in their own low-level module (stdlib-only imports) so both
# the encoder (`tns.py`) and the decoders (`types.py`) can import them without a
# circular dependency.

import datetime
from decimal import Decimal

from oracle.tns_consts import (
    TNS_TYPE_DATE, TNS_TYPE_NUMBER, TNS_TYPE_RAW, TNS_TYPE_VARCHAR,
)


class _DbType:
    """An Oracle bind type usable as a `cursor.var()` / OUT-bind type spec."""

    __slots__ = ("name", "tns_type", "default_size")

    def __init__(self, name: str, tns_type: int, default_size: int):
        self.name = name
        self.tns_type = tns_type
        self.default_size = default_size

    def __repr__(self) -> str:
        return self.name


# oracledb-compatible type-constant aliases for cursor.var() / OUT binds.
DB_TYPE_NUMBER = NUMBER = _DbType("DB_TYPE_NUMBER", TNS_TYPE_NUMBER, 22)
DB_TYPE_VARCHAR = STRING = _DbType("DB_TYPE_VARCHAR", TNS_TYPE_VARCHAR, 32767)
DB_TYPE_RAW = _DbType("DB_TYPE_RAW", TNS_TYPE_RAW, 32767)
DB_TYPE_DATE = _DbType("DB_TYPE_DATE", TNS_TYPE_DATE, 7)

_PYTYPE_TO_DBTYPE = {
    int: NUMBER, float: NUMBER, Decimal: NUMBER,
    str: STRING, bytes: DB_TYPE_RAW, bytearray: DB_TYPE_RAW,
    datetime.date: DB_TYPE_DATE, datetime.datetime: DB_TYPE_DATE,
}


def _resolve_dbtype(typ: object) -> _DbType:
    if isinstance(typ, _DbType):
        return typ
    if isinstance(typ, type) and typ in _PYTYPE_TO_DBTYPE:
        return _PYTYPE_TO_DBTYPE[typ]
    raise ValueError(f"unsupported var() type: {typ!r}")


class Var:
    """A bind container that can receive an OUT / IN OUT value.

    Create via `cursor.var(typ, size=None)`, where `typ` is a Python type
    (`int`, `str`, `bytes`, `datetime`, ...) or an `oracle.*` type constant.
    Pass it in a `callproc` / `execute` parameter list for an OUT or IN OUT
    argument; seed an IN OUT value with `setvalue(0, value)` and read the
    result afterwards with `getvalue()`.
    """

    __slots__ = ("dbtype", "size", "_value", "has_value")

    def __init__(self, typ: object, size: int | None = None):
        self.dbtype = _resolve_dbtype(typ)
        self.size = size if size is not None else self.dbtype.default_size
        self._value = None
        self.has_value = False

    def setvalue(self, pos: int, value: object) -> None:
        self._value = value
        self.has_value = True

    def getvalue(self, pos: int = 0) -> object:
        return self._value

    def __repr__(self) -> str:
        return f"Var({self.dbtype}, size={self.size}, value={self._value!r})"


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
        return f"BinaryFloat({float.__repr__(self)})"


class BinaryDouble(float):
    """Bind marker: send the value as a native BINARY_DOUBLE (64-bit IEEE-754)
    rather than the default NUMBER. See :class:`BinaryFloat`.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f"BinaryDouble({float.__repr__(self)})"


class IntervalYM:
    """An Oracle ``INTERVAL YEAR TO MONTH`` value.

    There is no stdlib type for a calendar interval (a month is not a fixed
    number of days), so this small class carries the two fields. It is used both
    as the decoded result of an interval-year-to-month column and as a bind
    input. Years and months are normalised on construction so that
    ``abs(months) < 12`` and both fields share the interval's sign, matching how
    the server stores and returns the value.
    """

    __slots__ = ("years", "months")

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
        return f"IntervalYM(years={self.years}, months={self.months})"
