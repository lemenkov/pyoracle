# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Decoders that turn the raw column bytes returned by the wire-level RXD parser
# into Python values. Each top-level function takes the raw `bytes` for one
# column value and returns the typed Python object (or None for NULL).
#
# Algorithms cross-referenced with python-oracledb's decoders.pyx.

import datetime
from decimal import Decimal

from oracle.tns_consts import (
    AL16UTF16_CHARSET, AL32UTF8_CHARSET, ISO_LATIN_1_CHARSET, UTF8_CHARSET,
    TNS_TYPE_CHAR, TNS_TYPE_DATE, TNS_TYPE_NUMBER, TNS_TYPE_TIMESTAMP,
    TNS_TYPE_TIMESTAMPLTZ, TNS_TYPE_TIMESTAMPTZ, TNS_TYPE_VARCHAR,
)

# Oracle stores a TZ offset as (hour + 20, minute + 60); a top bit set on the
# hour byte means "named region ID" which we don't resolve.
_TZ_HOUR_OFFSET = 20
_TZ_MINUTE_OFFSET = 60
_TZ_REGION_ID_FLAG = 0x80

_CHARSET_PYTHON_NAME = {
    ISO_LATIN_1_CHARSET: 'iso-8859-1',
    UTF8_CHARSET: 'utf-8',
    AL32UTF8_CHARSET: 'utf-8',
    AL16UTF16_CHARSET: 'utf-16-be',
}


def decode_number(Data: bytes) -> int | Decimal | None:
    # Oracle NUMBER is a base-100 floating point format. Byte 0 is the biased
    # exponent (with the sign bit in the top bit, *inverted* for negatives);
    # the remaining bytes are base-100 mantissa digits. Negatives carry a
    # trailing 0x66 terminator.
    if not Data:
        return None
    if len(Data) == 1:
        if Data[0] == 0x80:
            return 0
        # -1e126 is the canonical "maximum negative" sentinel; surface it as a
        # Decimal for fidelity.
        return Decimal('-1E126')

    ExpByte = Data[0]
    IsPositive = (ExpByte & 0x80) != 0
    if IsPositive:
        Exponent = (ExpByte & 0x7f) - 65
    else:
        Exponent = ((~ExpByte) & 0x7f) - 65

    Mantissa = Data[1:]
    if not IsPositive and Mantissa and Mantissa[-1] == 0x66:
        Mantissa = Mantissa[:-1]

    # Each mantissa byte is a two-digit base-100 group (00..99).
    Pairs = []
    for B in Mantissa:
        Pairs.append((B - 1) if IsPositive else (101 - B))

    # Build the unsigned decimal string from the digit pairs, then place the
    # decimal point based on the exponent. Exponent N means the first pair
    # represents 100**N, i.e. the integer part has (N + 1) pairs / (2N + 2)
    # digits before the decimal point.
    DigitString = ''.join(f'{P:02d}' for P in Pairs)
    IntegerDigits = (Exponent + 1) * 2

    if IntegerDigits >= len(DigitString):
        # No fractional part; pad trailing zeros and emit as int.
        IntegerPart = DigitString + '0' * (IntegerDigits - len(DigitString))
        FractionPart = ''
    elif IntegerDigits <= 0:
        # Pure fractional; pad leading zeros after the decimal point.
        IntegerPart = '0'
        FractionPart = '0' * (-IntegerDigits) + DigitString
    else:
        IntegerPart = DigitString[:IntegerDigits]
        FractionPart = DigitString[IntegerDigits:]

    IntegerPart = IntegerPart.lstrip('0') or '0'
    FractionPart = FractionPart.rstrip('0')
    Sign = '' if IsPositive else '-'

    if FractionPart:
        return Decimal(f'{Sign}{IntegerPart}.{FractionPart}')
    return int(f'{Sign}{IntegerPart}')


def decode_date(Data: bytes) -> datetime.datetime | None:
    # 7 bytes = DATE, 11 bytes adds 4-byte BE nanoseconds, 13 bytes adds a
    # 2-byte timezone offset. Year is split across two centuries-biased bytes.
    if not Data or len(Data) < 7:
        return None

    Year = (Data[0] - 100) * 100 + (Data[1] - 100)
    Month = Data[2]
    Day = Data[3]
    Hour = Data[4] - 1
    Minute = Data[5] - 1
    Second = Data[6] - 1

    Microsecond = 0
    if len(Data) >= 11:
        Nanos = int.from_bytes(Data[7:11], 'big')
        Microsecond = Nanos // 1000

    # For TIMESTAMP WITH TIME ZONE Oracle stores the wall clock in UTC and
    # tags it with the original session offset. To preserve the same instant
    # we build a UTC datetime first, then convert to the tagged offset so the
    # result both compares equal and prints with the original local time.
    Tz = None
    if len(Data) >= 13 and Data[11] != 0 and Data[12] != 0:
        if not (Data[11] & _TZ_REGION_ID_FLAG):
            TzHours = Data[11] - _TZ_HOUR_OFFSET
            TzMinutes = Data[12] - _TZ_MINUTE_OFFSET
            Tz = datetime.timezone(datetime.timedelta(hours=TzHours, minutes=TzMinutes))
        # Named region IDs (top bit of byte 11) would need the Oracle timezone
        # tables; fall through with Tz=None and surface as naive.

    if Tz is None:
        return datetime.datetime(Year, Month, Day, Hour, Minute, Second, Microsecond)

    Utc = datetime.datetime(Year, Month, Day, Hour, Minute, Second, Microsecond,
                            tzinfo=datetime.timezone.utc)
    return Utc.astimezone(Tz)


def decode_string(Data: bytes, Charset: int = AL32UTF8_CHARSET) -> str | None:
    if not Data:
        return None
    Encoding = _CHARSET_PYTHON_NAME.get(Charset, 'utf-8')
    return Data.decode(Encoding, errors='replace')


def decode_value(Column: dict, Data: bytes | list) -> object:
    # Dispatcher: pick the right decoder based on the column's TNS data type.
    # Unknown types are returned as raw bytes so callers can still see them.
    if Data is None or Data == [] or Data == b'':
        return None
    if isinstance(Data, list):
        return None
    DataType = Column.get('data_type')
    if DataType == TNS_TYPE_NUMBER:
        return decode_number(Data)
    if DataType in (TNS_TYPE_VARCHAR, TNS_TYPE_CHAR):
        return decode_string(Data, Column.get('charset', AL32UTF8_CHARSET))
    if DataType in (TNS_TYPE_DATE, TNS_TYPE_TIMESTAMP, TNS_TYPE_TIMESTAMPTZ,
                    TNS_TYPE_TIMESTAMPLTZ):
        return decode_date(Data)
    return Data
