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

from oracle.datatypes import (
    DB_TYPE_BINARY_DOUBLE, DB_TYPE_BINARY_FLOAT, DB_TYPE_INTERVAL_DS,
    DB_TYPE_INTERVAL_YM, DB_TYPE_TIMESTAMP, DB_TYPE_TIMESTAMP_TZ,
    BinaryDouble, BinaryFloat, IntervalYM, Var,
)
from oracle.tns import (
    _read_iov, _read_long_column, _read_rowid_column, _read_urowid_column,
    decode_dalc, decode_ub4, encode_sb4, exec_oac_signature,
    encode_token_binary_double, encode_token_binary_float,
    encode_token_interval_ds, encode_token_interval_ym, encode_token_oac,
    encode_token_rxd,
)
from oracle.tns_consts import (
    TNS_TYPE_BDOUBLE, TNS_TYPE_BFLOAT, TNS_TYPE_INTERVALDS, TNS_TYPE_INTERVALYM,
)
from oracle.types import (
    decode_binary_double, decode_binary_float, decode_interval_ds,
    decode_interval_ym, decode_value, rowid_to_string, urowid_to_string,
)


class TestDecodeUb4(unittest.TestCase):
    # PROTOCOL.md §12.1 variable-length integer.

    def test_zero(self):
        self.assertEqual(decode_ub4(b"\x00rest"), (0, b"rest"))

    def test_one_byte(self):
        self.assertEqual(decode_ub4(b"\x01\x7f"), (127, b""))

    def test_two_bytes(self):
        self.assertEqual(decode_ub4(b"\x02\x01\x00"), (256, b""))

    def test_three_bytes(self):
        self.assertEqual(decode_ub4(b"\x03\x01\x00\x00"), (65536, b""))

    def test_four_bytes(self):
        self.assertEqual(decode_ub4(b"\x04\xff\xff\xff\xff"), (4294967295, b""))

    def test_consumes_only_its_own_bytes(self):
        self.assertEqual(decode_ub4(b"\x02\x01\x00tail"), (256, b"tail"))

    def test_negative_single_byte(self):
        # NUMBER scale -127 arrives as 0x81 0x7f.
        self.assertEqual(decode_ub4(b"\x81\x7f"), (-127, b""))

    def test_negative_multibyte(self):
        # -256 needs two magnitude bytes: 0x82 0x01 0x00.
        self.assertEqual(decode_ub4(b"\x82\x01\x00"), (-256, b""))

    def test_negative_consumes_only_its_own_bytes(self):
        self.assertEqual(decode_ub4(b"\x82\x01\x00tail"), (-256, b"tail"))

    def test_roundtrip_with_encode_sb4(self):
        for value in (0, 1, 127, 255, 256, 65535, 65536, 16777215, 4294967295):
            self.assertEqual(decode_ub4(encode_sb4(value)), (value, b""))


class TestVarOacTypes(unittest.TestCase):
    # A Var(<type const>) OUT bind must declare the same OAC (type + buffer
    # size) the server would expect for a value of that type (issue #17).

    def test_timestamp(self):
        self.assertEqual(
            encode_token_oac(Var(DB_TYPE_TIMESTAMP)),
            encode_token_oac(datetime.datetime(2026, 6, 7, 1, 2, 3, 500000)))

    def test_timestamp_tz(self):
        tz = datetime.datetime(2026, 6, 7, 1, 2, 3,
                               tzinfo=datetime.timezone.utc)
        self.assertEqual(encode_token_oac(Var(DB_TYPE_TIMESTAMP_TZ)),
                         encode_token_oac(tz))

    def test_binary_float(self):
        self.assertEqual(encode_token_oac(Var(DB_TYPE_BINARY_FLOAT)),
                         encode_token_oac(BinaryFloat(1.0)))

    def test_binary_double(self):
        self.assertEqual(encode_token_oac(Var(DB_TYPE_BINARY_DOUBLE)),
                         encode_token_oac(BinaryDouble(1.0)))

    def test_interval_ds(self):
        self.assertEqual(encode_token_oac(Var(DB_TYPE_INTERVAL_DS)),
                         encode_token_oac(datetime.timedelta(days=1)))

    def test_interval_ym(self):
        self.assertEqual(encode_token_oac(Var(DB_TYPE_INTERVAL_YM)),
                         encode_token_oac(IntervalYM(1, 2)))

    def test_python_type_mappings_resolve(self):
        self.assertEqual(Var(datetime.timedelta).dbtype, DB_TYPE_INTERVAL_DS)
        self.assertEqual(Var(IntervalYM).dbtype, DB_TYPE_INTERVAL_YM)


class TestExecOacSignature(unittest.TestCase):
    # The DML cursor-cache key includes this signature so a cached cursor is
    # only reused for binds matching the OAC it was parsed with. Two binds that
    # would need a differently-sized OAC MUST produce different signatures, or
    # the cached re-execute (which omits the OAC) overflows the frozen bind
    # buffer and the server raises ORA-01461.

    def test_empty_bind(self):
        self.assertEqual(exec_oac_signature([], []), b"")

    def test_same_length_strings_match(self):
        self.assertEqual(exec_oac_signature([1, "abcd"], []),
                         exec_oac_signature([2, "wxyz"], []))

    def test_different_length_strings_differ(self):
        # "row9" (4 bytes) vs "row10" (5 bytes) — the exact case that tripped
        # ORA-01461 on a cached re-execute.
        self.assertNotEqual(exec_oac_signature([9, "row9"], []),
                            exec_oac_signature([10, "row10"], []))

    def test_number_value_does_not_affect_signature(self):
        # NUMBER is fixed-width, so a bigger integer keeps the same signature.
        self.assertEqual(exec_oac_signature([1], []),
                         exec_oac_signature([999999999], []))

    def test_str_vs_bytes_differ(self):
        self.assertNotEqual(exec_oac_signature(["abc"], []),
                            exec_oac_signature([b"abc"], []))

    def test_batch_uses_widest_row(self):
        # Array DML sizes the single OAC to the widest value across all rows,
        # so a batch whose widest string grows gets a different signature.
        narrow = exec_oac_signature([1, "a"], [[2, "bb"]])
        wide = exec_oac_signature([1, "a"], [[2, "bbbbb"]])
        self.assertNotEqual(narrow, wide)


class TestDecodeDalc(unittest.TestCase):
    # PROTOCOL.md §12.2 Data with Attached Length Code.

    def test_empty(self):
        self.assertEqual(decode_dalc(b"\x00tail"), ([], b"tail"))

    def test_null_marker(self):
        # 0xFF null marker carries no data; reported like empty.
        self.assertEqual(decode_dalc(b"\xfftail"), ([], b"tail"))

    def test_direct_length(self):
        self.assertEqual(decode_dalc(b"\x03abctail"), (b"abc", b"tail"))


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


class TestUrowid(unittest.TestCase):
    # Bytes captured from a live XE index-organized table row whose SELECT
    # ROWID was "*BAEAGYMCwQL+" (type tag 0x02 + 9 rowid bytes carrying the
    # NUMBER primary key c1 02).

    def test_urowid_to_string(self):
        self.assertEqual(
            urowid_to_string(bytes.fromhex("02040100198302c102fe")),
            "*BAEAGYMCwQL+")

    def test_read_urowid_column(self):
        # ub4 num_bytes (0x0a) + 1-byte echo (0x0a) + 10 value bytes, then a
        # trailing NUMBER that must be left for the next column.
        Wire = bytes.fromhex("010a0a02040100198302c102fe") + bytes.fromhex("02c102")
        Value, Rest = _read_urowid_column(Wire)
        self.assertEqual(Value, "*BAEAGYMCwQL+")
        self.assertEqual(Rest, bytes.fromhex("02c102"))

    def test_read_urowid_null(self):
        Value, Rest = _read_urowid_column(b"\x00\x05rest!")
        self.assertIsNone(Value)
        self.assertEqual(Rest, b"\x05rest!")


class TestLong(unittest.TestCase):
    # Bytes captured from live XE rows (value portion + the two trailing ub4
    # indicators), with a trailing 0x04 / NUMBER standing in for the next token
    # so we can assert the reader leaves the stream aligned.

    def test_long_single(self):
        Val, Rest = _read_long_column(bytes.fromhex("fe015a00000004"))
        self.assertEqual(Val, b"Z")
        self.assertEqual(Rest, b"\x04")

    def test_long_then_number(self):
        # 'AB' value, terminator 00, trailer 00 00, then NUMBER 02 c1 02 which
        # must be left intact for the next column.
        Val, Rest = _read_long_column(bytes.fromhex("fe02414200000002c102"))
        self.assertEqual(Val, b"AB")
        self.assertEqual(Rest, bytes.fromhex("02c102"))

    def test_long_multichunk(self):
        # Two chunks "AB" + "CD" then the zero terminator and two ub4 trailers.
        Val, Rest = _read_long_column(bytes.fromhex("fe0241420243440000000a"))
        self.assertEqual(Val, b"ABCD")
        self.assertEqual(Rest, b"\x0a")

    def test_long_null(self):
        # NULL value (0x00) then the two ub4 indicators 81 01 / 02 05 7d, then
        # a following NUMBER 02 c1 64.
        Val, Rest = _read_long_column(bytes.fromhex("00810102057d02c164"))
        self.assertIsNone(Val)
        self.assertEqual(Rest, bytes.fromhex("02c164"))

    def test_decode_value_long_is_str(self):
        from oracle.tns_consts import TNS_TYPE_LONG
        self.assertEqual(decode_value({'data_type': TNS_TYPE_LONG}, b"hi"), "hi")

    def test_decode_value_longraw_is_bytes(self):
        from oracle.tns_consts import TNS_TYPE_LONGRAW
        Out = decode_value({'data_type': TNS_TYPE_LONGRAW}, b"\xde\xad")
        self.assertEqual(Out, b"\xde\xad")
        self.assertIsInstance(Out, bytes)


class TestPasswordRedaction(unittest.TestCase):
    # The bind/handshake dicts carry the password so the encoders can use it;
    # it must never reach a debug log in clear text (CodeQL
    # py/clear-text-logging-sensitive-data).

    def test_redacted_masks_password(self):
        from oracle.tns import _redacted
        out = _redacted({'env': {'user': 'u', 'password': 'secret'}})
        self.assertEqual(out['env']['password'], '***')
        self.assertEqual(out['env']['user'], 'u')

    def test_description_debug_log_omits_password(self):
        from oracle.tns import encode_dictionary_description
        d = {'env': {'user': 'scott', 'password': 'tiger', 'host': 'h',
                     'port': 1521, 'sid': '', 'service_name': 'XE',
                     'app_name': 'pyoracle', 'ssl': None}, 'seq': 1}
        with self.assertLogs('oracle.tns', level='DEBUG') as cm:
            encode_dictionary_description(d)
        joined = '\n'.join(cm.output)
        self.assertNotIn('tiger', joined)
        self.assertIn('***', joined)


class TestRefCursor(unittest.TestCase):
    # A TTI_IOV captured from XE 11g for BEGIN pyo_refcur(:1); END; where the
    # proc opens a cursor over SELECT 1 a, 'x' b ... (one OUT REF CURSOR bind).
    WIRE = bytes.fromhex(
        "0b05010100010100000010074c0103010251020000817f0102000000000000"
        "0001010101014100000000608000000101000000000203690101010101010101"
        "420000010100010707787e0606100d040000000000010200080106031a0a6400"
        "010101020000000000040105010401010000000101002f00000000000000000000"
        "00000700010100000000")

    def test_refcursor_iov_parse(self):
        from oracle.cursor import cursor as RefCur
        from oracle.tns import _read_iov
        directions, out_values, _ = _read_iov(self.WIRE, [RefCur()])
        self.assertEqual(directions, [16])               # one OUT bind
        self.assertEqual(len(out_values), 1)
        marker = out_values[0]
        self.assertTrue(marker.get("_refcursor"))
        self.assertIsInstance(marker["cursor_id"], int)
        self.assertGreater(marker["cursor_id"], 0)
        self.assertEqual([c.get("column_name") for c in marker["row_format"]],
                         [b"A", b"B"])

    def test_scalar_bind_not_treated_as_refcursor(self):
        # Without a REF CURSOR bind, a scalar OUT value stays raw bytes.
        from oracle.tns import _read_iov
        wire = bytes([0x0b, 0x05, 0x01, 0x01, 0x00, 0x01, 0x01,
                      0x00, 0x00, 0x00, 0x10,
                      0x07, 0x02, 0xc1, 0x64, 0x00, 0x08])
        _, out_values, _ = _read_iov(wire, [None])
        self.assertEqual(out_values, [b"\xc1\x64"])


class TestVar(unittest.TestCase):
    def test_var_python_type(self):
        from oracle.datatypes import Var
        from oracle.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
        self.assertEqual(Var(int).dbtype.tns_type, TNS_TYPE_NUMBER)
        self.assertEqual(Var(str).dbtype.tns_type, TNS_TYPE_VARCHAR)

    def test_var_type_constant(self):
        from oracle.datatypes import NUMBER, STRING, Var
        from oracle.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
        self.assertEqual(Var(NUMBER).dbtype.tns_type, TNS_TYPE_NUMBER)
        self.assertEqual(Var(STRING).dbtype.tns_type, TNS_TYPE_VARCHAR)

    def test_var_size_default_and_override(self):
        from oracle.datatypes import Var
        self.assertEqual(Var(int).size, 22)
        self.assertEqual(Var(str).size, 32767)
        self.assertEqual(Var(str, 100).size, 100)

    def test_var_setget(self):
        from oracle.datatypes import Var
        v = Var(int)
        self.assertIsNone(v.getvalue())
        self.assertFalse(v.has_value)
        v.setvalue(0, 5)
        self.assertEqual(v.getvalue(), 5)
        self.assertTrue(v.has_value)

    def test_var_oac_by_declared_type(self):
        # OAC type comes from the Var's type even when the value is NULL.
        from oracle.datatypes import Var
        from oracle.tns_consts import TNS_TYPE_NUMBER, TNS_TYPE_VARCHAR
        self.assertEqual(encode_token_oac(Var(int))[0], TNS_TYPE_NUMBER)
        self.assertEqual(encode_token_oac(Var(str))[0], TNS_TYPE_VARCHAR)

    def test_var_rxd_null_when_unseeded(self):
        from oracle.datatypes import Var
        self.assertEqual(encode_token_rxd(Var(int)), bytes([0]))

    def test_var_rxd_seeded_value(self):
        from oracle.datatypes import Var
        v = Var(int); v.setvalue(0, 5)
        self.assertEqual(encode_token_rxd(v), encode_token_rxd(5))


class TestIov(unittest.TestCase):
    # TTI_IOV bodies captured from XE 11g. Common header is
    #   0b 05 01 <numreq> 00 01 01 00 00 00  then per-bind direction byte(s),
    # then (if any OUT bind) 07 (RXD) + per-OUT-value [DALC][indicator].
    # A trailing 0x08 (RPA) stands in for the tokens that follow.

    def test_in_only(self):
        # one IN bind (direction 32) -> no values, no RXD.
        wire = bytes([0x0b, 0x05, 0x01, 0x01, 0x00, 0x01, 0x01,
                      0x00, 0x00, 0x00, 0x20, 0x08])
        directions, out_values, rest = _read_iov(wire)
        self.assertEqual(directions, [32])
        self.assertEqual(out_values, [])
        self.assertEqual(rest, b"\x08")

    def test_single_out(self):
        # one OUT bind (16) returning NUMBER 99 (c1 64).
        wire = bytes([0x0b, 0x05, 0x01, 0x01, 0x00, 0x01, 0x01,
                      0x00, 0x00, 0x00, 0x10,
                      0x07, 0x02, 0xc1, 0x64, 0x00, 0x08])
        directions, out_values, rest = _read_iov(wire)
        self.assertEqual(directions, [16])
        self.assertEqual(out_values, [b"\xc1\x64"])
        self.assertEqual(rest, b"\x08")

    def test_out_and_inout(self):
        # OUT NUMBER 10 (c1 0b) + IN OUT VARCHAR "hi!".
        wire = bytes([0x0b, 0x05, 0x01, 0x02, 0x00, 0x01, 0x01,
                      0x00, 0x00, 0x00, 0x10, 0x30,
                      0x07, 0x02, 0xc1, 0x0b, 0x00,
                      0x03, 0x68, 0x69, 0x21, 0x00, 0x08])
        directions, out_values, rest = _read_iov(wire)
        self.assertEqual(directions, [16, 48])
        self.assertEqual(out_values, [b"\xc1\x0b", b"hi!"])
        self.assertEqual(rest, b"\x08")


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
