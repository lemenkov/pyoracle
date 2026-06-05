# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline round-trip tests for the native scalar bind/fetch types:
# BINARY_FLOAT, BINARY_DOUBLE, INTERVAL DAY TO SECOND, INTERVAL YEAR TO MONTH.
#
# The expected wire bytes are not invented: they were captured from a live
# Oracle XE by selecting columns of each type (the decoder falls through to raw
# bytes for unknown types, so a plain SELECT reveals the on-wire format).

import datetime
import math
import unittest

from oracle.datatypes import BinaryDouble, BinaryFloat, IntervalYM
from oracle.tns import (
    _read_rowid_column, encode_token_binary_double, encode_token_binary_float,
    encode_token_interval_ds, encode_token_interval_ym, encode_token_oac,
    encode_token_rxd,
)
from oracle.tns_consts import (
    TNS_TYPE_BDOUBLE, TNS_TYPE_BFLOAT, TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM,
)
from oracle.types import (
    decode_binary_double, decode_binary_float, decode_interval_ds,
    decode_interval_ym, rowid_to_string,
)


class TestBinaryFloat(unittest.TestCase):

    def test_encode_positive(self):
        self.assertEqual(encode_token_binary_float(BinaryFloat(1.5)),
                         bytes.fromhex("bfc00000"))

    def test_encode_negative(self):
        self.assertEqual(encode_token_binary_float(BinaryFloat(-2.25)),
                         bytes.fromhex("3fefffff"))

    def test_decode_positive(self):
        self.assertEqual(decode_binary_float(bytes.fromhex("bfc00000")), 1.5)

    def test_decode_negative(self):
        self.assertEqual(decode_binary_float(bytes.fromhex("3fefffff")), -2.25)

    def test_decode_empty_is_none(self):
        self.assertIsNone(decode_binary_float(b""))

    def test_roundtrip_inf(self):
        Wire = encode_token_binary_float(BinaryFloat(math.inf))
        self.assertEqual(decode_binary_float(Wire), math.inf)

    def test_roundtrip_neg_inf(self):
        Wire = encode_token_binary_float(BinaryFloat(-math.inf))
        self.assertEqual(decode_binary_float(Wire), -math.inf)

    def test_roundtrip_nan(self):
        Wire = encode_token_binary_float(BinaryFloat(math.nan))
        self.assertTrue(math.isnan(decode_binary_float(Wire)))


class TestBinaryDouble(unittest.TestCase):

    def test_encode_positive(self):
        self.assertEqual(encode_token_binary_double(BinaryDouble(1.5)),
                         bytes.fromhex("bff8000000000000"))

    def test_encode_negative(self):
        self.assertEqual(encode_token_binary_double(BinaryDouble(-1234.5678)),
                         bytes.fromhex("3f6cb5ba92a30552"))

    def test_decode_positive(self):
        self.assertEqual(decode_binary_double(bytes.fromhex("bff8000000000000")),
                         1.5)

    def test_decode_negative(self):
        self.assertEqual(
            decode_binary_double(bytes.fromhex("3f6cb5ba92a30552")), -1234.5678)

    def test_roundtrip_specials(self):
        for V in (math.inf, -math.inf, 0.0, -0.0):
            self.assertEqual(
                decode_binary_double(encode_token_binary_double(BinaryDouble(V))),
                V)
        self.assertTrue(math.isnan(
            decode_binary_double(encode_token_binary_double(BinaryDouble(math.nan)))))


class TestIntervalDS(unittest.TestCase):

    def test_encode_positive(self):
        TD = datetime.timedelta(days=5, hours=4, minutes=3, seconds=2,
                                microseconds=123456)
        self.assertEqual(encode_token_interval_ds(TD),
                         bytes.fromhex("80000005403f3e875bca00"))

    def test_encode_negative(self):
        self.assertEqual(
            encode_token_interval_ds(datetime.timedelta(seconds=-1.5)),
            bytes.fromhex("800000003c3c3b62329b00"))

    def test_decode_positive(self):
        self.assertEqual(
            decode_interval_ds(bytes.fromhex("80000005403f3e875bca00")),
            datetime.timedelta(days=5, hours=4, minutes=3, seconds=2,
                               microseconds=123456))

    def test_decode_negative(self):
        self.assertEqual(
            decode_interval_ds(bytes.fromhex("800000003c3c3b62329b00")),
            datetime.timedelta(seconds=-1.5))

    def test_roundtrip(self):
        for TD in (datetime.timedelta(0),
                   datetime.timedelta(days=-3, hours=-2),
                   datetime.timedelta(days=400, microseconds=999999)):
            self.assertEqual(
                decode_interval_ds(encode_token_interval_ds(TD)), TD)


class TestIntervalYM(unittest.TestCase):

    def test_encode_positive(self):
        self.assertEqual(encode_token_interval_ym(IntervalYM(3, 7)),
                         bytes.fromhex("8000000343"))

    def test_encode_negative(self):
        self.assertEqual(encode_token_interval_ym(IntervalYM(-1, -2)),
                         bytes.fromhex("7fffffff3a"))

    def test_decode_positive(self):
        self.assertEqual(decode_interval_ym(bytes.fromhex("8000000343")),
                         IntervalYM(3, 7))

    def test_decode_negative(self):
        self.assertEqual(decode_interval_ym(bytes.fromhex("7fffffff3a")),
                         IntervalYM(-1, -2))

    def test_normalisation(self):
        self.assertEqual(IntervalYM(0, 14), IntervalYM(1, 2))
        self.assertEqual(IntervalYM(0, -14), IntervalYM(-1, -2))
        iv = IntervalYM(0, 14)
        self.assertEqual((iv.years, iv.months), (1, 2))

    def test_roundtrip(self):
        for iv in (IntervalYM(0, 0), IntervalYM(2, 0), IntervalYM(0, 14),
                   IntervalYM(-5, -11)):
            self.assertEqual(
                decode_interval_ym(encode_token_interval_ym(iv)), iv)


class TestRowid(unittest.TestCase):
    # Bytes captured from a live XE row whose ROWIDTOCHAR was
    # "AAAK6JAAEAAACGPAAA" (obj 44681, file 4, block 8591, slot 0).

    def test_rowid_to_string(self):
        self.assertEqual(rowid_to_string(44681, 4, 8591, 0),
                         "AAAK6JAAEAAACGPAAA")

    def test_rowid_to_string_slot(self):
        # Slot increments map to the trailing base64 digit.
        self.assertEqual(rowid_to_string(44681, 4, 8591, 4)[-3:], "AAE")

    def test_read_rowid_column(self):
        # 1-byte present indicator (0x0e) + structured rowid, then a trailing
        # byte that must be left for the next token.
        Wire = bytes.fromhex("0e02ae8901040002218f00") + b"\x08"
        Value, Rest = _read_rowid_column(Wire)
        self.assertEqual(Value, "AAAK6JAAEAAACGPAAA")
        self.assertEqual(Rest, b"\x08")

    def test_read_rowid_null(self):
        Value, Rest = _read_rowid_column(b"\x00\x04rest")
        self.assertIsNone(Value)
        self.assertEqual(Rest, b"\x04rest")


class TestBindDispatch(unittest.TestCase):
    # The RXD value bytes carry a 1-byte length prefix; the OAC descriptor
    # leads with the data-type code. Confirm each Python type dispatches to the
    # right wire type.

    def test_binary_float_dispatch(self):
        self.assertEqual(encode_token_rxd(BinaryFloat(1.5))[0], 4)
        self.assertEqual(encode_token_oac(BinaryFloat(1.5))[0], TNS_TYPE_BFLOAT)

    def test_binary_double_dispatch(self):
        self.assertEqual(encode_token_rxd(BinaryDouble(1.5))[0], 8)
        self.assertEqual(encode_token_oac(BinaryDouble(1.5))[0], TNS_TYPE_BDOUBLE)

    def test_timedelta_dispatch(self):
        TD = datetime.timedelta(days=1)
        self.assertEqual(encode_token_rxd(TD)[0], 11)
        self.assertEqual(encode_token_oac(TD)[0], TNS_TYPE_INTERVALDS)

    def test_intervalym_dispatch(self):
        self.assertEqual(encode_token_rxd(IntervalYM(1, 0))[0], 5)
        self.assertEqual(encode_token_oac(IntervalYM(1, 0))[0], TNS_TYPE_INTERVALYM)

    def test_nonfinite_plain_float_autoroutes_to_bdouble(self):
        # A plain float (no wrapper) that is inf/nan must bind as BINARY_DOUBLE
        # rather than crashing the base-100 NUMBER encoder.
        for V in (math.inf, -math.inf, math.nan):
            self.assertEqual(encode_token_rxd(V)[0], 8)
            self.assertEqual(encode_token_oac(V)[0], TNS_TYPE_BDOUBLE)

    def test_finite_plain_float_stays_number(self):
        from oracle.tns_consts import TNS_TYPE_NUMBER
        self.assertEqual(encode_token_oac(1.5)[0], TNS_TYPE_NUMBER)


if __name__ == "__main__":
    unittest.main()
