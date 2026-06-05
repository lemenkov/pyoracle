# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Public value/marker types for binds and fetches that have no faithful stdlib
# equivalent. Kept in their own low-level module (stdlib-only imports) so both
# the encoder (`tns.py`) and the decoders (`types.py`) can import them without a
# circular dependency.


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
