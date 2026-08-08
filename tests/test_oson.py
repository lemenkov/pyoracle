# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the OSON (native JSON) decoder.

Each fixture is a real OSON image captured from a live Oracle 21c server for a
known JSON document (see docs/PROTOCOL.md §15). No server is needed to run
these — they pin the decoder against the actual wire format.
"""

import datetime
import json
import unittest
from decimal import Decimal

from oracle.datatypes import IntervalYM
from oracle.oson import OsonError, decode_oson, encode_oson, json_to_text

# (label, JSON document, captured OSON image as hex)
FIXTURES = [
    ('null', 'null', 'ff4a5a010016000130'),
    ('true', 'true', 'ff4a5a010016000131'),
    ('false', 'false', 'ff4a5a010016000132'),
    ('num_small', '1', 'ff4a5a010016000321c102'),
    ('num_42', '42', 'ff4a5a010016000321c12b'),
    ('num_neg', '-7', 'ff4a5a0100160004223e5e66'),
    ('num_frac', '3.14', 'ff4a5a010016000422c1040f'),
    ('float_e', '1.5e10', 'ff4a5a010016000422c60233'),
    ('zero', '0', 'ff4a5a01001600022080'),
    ('bigint', '123456789012345', 'ff4a5a010016000b3409c802182e445a02182e'),
    ('str_short', '"hi"', 'ff4a5a0100160003026869'),
    ('str_world', '"world"', 'ff4a5a010016000605776f726c64'),
    ('str_long', '"' + 'x' * 50 + '"', 'ff4a5a01001600343332' + '78' * 50),
    ('str_unicode', '"café—€"', 'ff4a5a010016000c0b636166c3a9e28094e282ac'),
    ('arr_empty', '[]', 'ff4a5a01200600000000020001c000'),
    ('obj_empty', '{}', 'ff4a5a012006000000000200018400'),
    ('obj_one', '{"a":1}', 'ff4a5a012106010002000800002c00000161840101000521c102'),
    (
        'arr_ints',
        '[1,2,3]',
        'ff4a5a01200600000000110000c0030008000b000e21c10221c10321c104',
    ),
    (
        'two_keys',
        '{"k1":10,"k2":20}',
        'ff4a5a012106020006000e000008c100030000026b31026b32840202010008'
        '000b21c10b21c115',
    ),
    (
        'obj_mix',
        '{"hello":"world","n":42,"arr":[1,2,3]}',
        'ff4a5a01210603000c002500001831ab0008000600000568656c6c6f016e03'
        '6172728403030201000b0011001405776f726c6421c12bc003001c001f0022'
        '21c10221c10321c104',
    ),
    (
        'nested',
        '{"a":{"b":[true,null,"x"]}}',
        'ff4a5a012106020004001600002ce500000002016101628401010005840102'
        '000ac00300120013001431300178',
    ),
    (
        'deep_str',
        '{"msg":"the quick brown fox jumps over"}',
        'ff4a5a01210601000400240000020000036d736784010100051e7468652071'
        '7569636b2062726f776e20666f78206a756d7073206f766572',
    ),
    (
        'big_arr',
        json.dumps(list(range(40))),
        'ff4a5a01200600000000c90000c028005200540057005a005d006000630066'
        '0069006c006f007200750078007b007e008100840087008a008d0090009300'
        '960099009c009f00a200a500a800ab00ae00b100b400b700ba00bd00c000c3'
        '00c6208021c10221c10321c10421c10521c10621c10721c10821c10921c10a'
        '21c10b21c10c21c10d21c10e21c10f21c11021c11121c11221c11321c11421'
        'c11521c11621c11721c11821c11921c11a21c11b21c11c21c11d21c11e21c1'
        '1f21c12021c12121c12221c12321c12421c12521c12621c12721c128',
    ),
]


def _norm(value):
    # Oracle NUMBER decodes to Decimal for fidelity; normalise to int/float so
    # the captured docs compare equal to json.loads of the source text.
    if isinstance(value, Decimal):
        i = int(value)
        return i if value == i else float(value)
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_norm(v) for v in value]
    return value


class TestOsonDecode(unittest.TestCase):
    def test_fixtures(self):
        for label, doc, hexstr in FIXTURES:
            with self.subTest(label=label):
                got = _norm(decode_oson(bytes.fromhex(hexstr)))
                self.assertEqual(got, json.loads(doc))

    def test_bad_magic_raises(self):
        with self.assertRaises(OsonError):
            decode_oson(b'\x00\x01\x02\x03\x04\x05')

    def test_truncated_image_raises_osonerror(self):
        # A structurally short image must raise OsonError, not leak the raw
        # IndexError of an out-of-range read (the SeerODBC fuzzer found the C
        # analog of this as a header overread). Each case is valid magic
        # followed by a header/body cut short at a different point.
        MAGIC = 'ff4a5a01'
        cases = {
            'magic only': MAGIC,
            'tree flag, no header body': MAGIC + '2004',
            'ub4-tree-size flag, header cut short': MAGIC + '3004' + '010005',
            'num_fnames=255, body truncated': MAGIC + '2004' + 'ff' + '000000000000',
            'bare scalar, size overruns': MAGIC + '0000' + '00ff',
        }
        for label, hexstr in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(OsonError):
                    decode_oson(bytes.fromhex(hexstr))

    def test_value_types(self):
        # Spot-check the concrete Python types, not just equality.
        d = decode_oson(
            bytes.fromhex(
                'ff4a5a01210603000c002500001831ab0008000600000568656c6c6f016e03'
                '6172728403030201000b0011001405776f726c6421c12bc003001c001f0022'
                '21c10221c10321c104'
            )
        )
        self.assertEqual(d['hello'], 'world')
        self.assertEqual(d['arr'], [1, 2, 3])
        self.assertIsInstance(d['arr'], list)
        self.assertIsInstance(d, dict)


class TestOsonBoundedDecode(unittest.TestCase):
    # A malformed OSON image must never hang the client (#165). Two unbounded
    # vectors are guarded: an out-of-range container count (a crafted ub4 count
    # would otherwise spin building a multi-billion-entry offset list) and a
    # cyclic / shared node offset (which would otherwise recurse forever or
    # blow up exponentially). Both must raise OsonError promptly.

    def test_oversized_container_count_raises(self):
        # Array nodes with a ub4 count of 0xffffffff, from SeerODBC's fuzz
        # corpus -- these spun decode_oson for >30s before the count bound.
        for hx in (
            'ff4a5a0092fff140ffffffffa5000000250000002500000025000000250000'
            '002500000025000000257fffffda00000025400000250000002500000000000'
            '025b500a9ff',
            'ff4a5a0004a50031ffffffffa5000000250000002500002500004000000460fa'
            '00315e2400ff4a5a5b00c93e3e3e9b9b9b9aa2259b77fe9b9b',
        ):
            with self.subTest(hx=hx[:16]):
                with self.assertRaises(OsonError):
                    decode_oson(bytes.fromhex(hx))

    def test_cyclic_node_offset_raises(self):
        # A tree image whose root array's sole element offset points back to the
        # array itself (offset 0) -- the cycle guard must reject it.
        with self.assertRaises(OsonError):
            decode_oson(bytes.fromhex('ff4a5a01200400000000040000c4010000'))

    def test_invalid_utf8_string_raises_osonerror(self):
        # Bare-scalar image with a 2-byte inline string node of invalid UTF-8
        # (0xff 0xff) -- must raise OsonError, not a raw UnicodeDecodeError (#230).
        with self.assertRaises(OsonError):
            decode_oson(bytes.fromhex('ff4a5a010016000302ffff'))

    def test_object_node_in_scalar_image_raises_osonerror(self):
        # Bare-scalar image whose node is an object container: there is no
        # field-name table, so resolving keys would call None(...) -> TypeError;
        # must raise OsonError instead (#230).
        with self.assertRaises(OsonError):
            decode_oson(bytes.fromhex('ff4a5a01001600058401010000'))


class TestOsonExtendedScalars(unittest.TestCase):
    # Native extended scalar nodes (#69), captured from JSON_SCALAR(<native>)
    # images on 21c. Each is a bare-scalar OSON image (flags 0x0016): a tag byte
    # then a fixed-width Oracle binary value.
    def test_binary_double(self):
        self.assertEqual(
            decode_oson(bytes.fromhex('ff4a5a010016000936bff8000000000000')), 1.5
        )

    def test_binary_float(self):
        self.assertEqual(decode_oson(bytes.fromhex('ff4a5a01001600057fc0200000')), 2.5)

    def test_date(self):
        self.assertEqual(
            decode_oson(bytes.fromhex('ff4a5a01001600083c787c060f010101')),
            datetime.datetime(2024, 6, 15, 0, 0, 0),
        )

    def test_timestamp(self):
        self.assertEqual(
            decode_oson(bytes.fromhex('ff4a5a010016000c39787e060f0d340f2faabe58')),
            datetime.datetime(2026, 6, 15, 12, 51, 14, 799719),
        )

    def test_timestamp_tz(self):
        got = decode_oson(bytes.fromhex('ff4a5a010016000e7c787e060f0d323135cad020143c'))
        self.assertEqual(
            got,
            datetime.datetime(
                2026, 6, 15, 12, 49, 48, 902484, tzinfo=datetime.timezone.utc
            ),
        )

    def test_interval_ds(self):
        self.assertEqual(
            decode_oson(bytes.fromhex('ff4a5a010016000c3e800000023c3c3c80000000')),
            datetime.timedelta(days=2),
        )

    def test_interval_ym(self):
        self.assertEqual(
            decode_oson(bytes.fromhex('ff4a5a01001600063d800000033e')), IntervalYM(3, 2)
        )


class TestOsonUb4Offsets(unittest.TestCase):
    # ub4 container value-offsets (#69): oracledb-produced images clear the
    # compact-offset flag (flags 0x2102) and use 4-byte offsets; the ub2 reader
    # used to mis-read them and recurse. Fixtures captured from oracledb native
    # JSON binds on 21c.
    def test_ub4_object(self):
        self.assertEqual(
            decode_oson(
                bytes.fromhex(
                    'ff4a5a012102020004001400002ce50000000201610162a40201020000000c'
                    '000000103402c1023402c103'
                )
            ),
            {'a': 1, 'b': 2},
        )

    def test_ub4_array(self):
        self.assertEqual(
            decode_oson(
                bytes.fromhex(
                    'ff4a5a01210200000000260000e005000000160000001a0000001e0000002200'
                    '0000253402c1023402c1033402c10433017831'
                )
            ),
            [1, 2, 3, 'x', True],
        )

    def test_ub4_object_with_date_and_extended(self):
        # ub4 offsets + the 0x7D DATE tag variant + mixed scalars.
        got = decode_oson(
            bytes.fromhex(
                'ff4a5a01210204000a002b0000133170820000000600030008026264027473'
                '016e0173a40401030204000000160000001b00000023000000273403c10233'
                '7d787c060f0d01013402c10833026869'
            )
        )
        self.assertEqual(
            got,
            {
                'bd': Decimal('1.5'),
                'ts': datetime.datetime(2024, 6, 15, 12, 0, 0),
                'n': 7,
                's': 'hi',
            },
        )


class TestJsonToText(unittest.TestCase):
    # json_to_text serialises a JSON bind value (#50) to text for a string bind.

    def test_basic_types(self):
        self.assertEqual(
            json_to_text({'a': 1, 'b': [True, None]}), '{"a": 1, "b": [true, null]}'
        )

    def test_decimal_integral_and_fractional(self):
        # Integral Decimal stays an exact int; fractional goes through float.
        self.assertEqual(json_to_text({'q': Decimal('3')}), '{"q": 3}')
        self.assertEqual(json_to_text(Decimal('19.99')), '19.99')

    def test_non_ascii_kept_utf8(self):
        # ensure_ascii=False keeps the emoji as UTF-8, not a \\u escape.
        self.assertEqual(json_to_text({'x': 'héllo😀'}), '{"x": "héllo😀"}')

    def test_unserialisable_raises(self):
        with self.assertRaises(TypeError):
            json_to_text({'d': object()})


class TestEncodeOson(unittest.TestCase):
    # encode_oson builds the OSON image for a native JSON bind (#70). It is the
    # inverse of decode_oson, so every encodable value must round-trip through
    # the existing decoder (which is itself pinned to captured server images).

    def _roundtrip(self, value):
        self.assertEqual(decode_oson(encode_oson(value)), value)

    def test_scalars(self):
        for v in (
            None,
            True,
            False,
            42,
            -7,
            1.5,
            'x',
            'scalar',
            Decimal('19.99'),
            'x' * 0x1F,
            'y' * 0x20,
        ):
            with self.subTest(v=v):
                self._roundtrip(v)

    def test_objects(self):
        self._roundtrip({'a': 1, 'b': 'hi'})
        self._roundtrip({'price': Decimal('19.99')})
        self._roundtrip({'on': True, 'off': False, 'nil': None})

    def test_arrays(self):
        self._roundtrip([1, 2, 'x', True, None])
        self._roundtrip([])

    def test_nested(self):
        self._roundtrip({'k': [1, {'m': 2}]})
        self._roundtrip([{'a': 1}, {'a': 2}])

    def test_wide_object_roundtrips_via_decode(self):
        # 200 keys still fits the ub1 count; verify both encode and decode.
        self._roundtrip({f'k{i:03d}': i for i in range(200)})

    def test_oversized_falls_back_with_osonerror(self):
        # The bind path relies on these raising so it can use the text cast.
        with self.assertRaises(OsonError):
            encode_oson('x' * 256)  # string past ub1 length
        with self.assertRaises(OsonError):
            encode_oson({f'k{i}': i for i in range(256)})  # > 255 keys
        with self.assertRaises(OsonError):
            encode_oson(list(range(256)))  # > 255 array entries

    def test_non_string_key_raises(self):
        with self.assertRaises(OsonError):
            encode_oson({1: 'a'})


class TestDecodeOsonLarge(unittest.TestCase):
    # Large-document decode (#88): strings >255 B and trees >64 KiB. The ub2/ub4
    # string nodes are pinned against a real 10.2-style image captured from 21c;
    # the ub4 tree/count/offset header bytes are written explicitly per the
    # format reverse-engineered from live 21c images (the real ones are >64 KiB,
    # too large to embed — JSONIntegration exercises those against the server).

    def test_ub2_string_node_0x37(self):
        # Captured 21c image for {"s": "x"*500}: object node, value is a 0x37
        # string with a ub2 length (0x01f4 = 500). Prefix is the real captured
        # header/nodes; the 500-byte body is the known 'x' run.
        Resp = (
            bytes.fromhex('ff4a5a01210601000201fc0000820000017384010100053701f4')
            + b'x' * 500
        )
        self.assertEqual(decode_oson(Resp), {'s': 'x' * 500})

    def test_ub4_string_node_0x38(self):
        # 0x38 = string with a ub4 length prefix (used for values >64 KiB);
        # exercised here as a bare scalar with a short body.
        Resp = bytes.fromhex('ff4a5a010000000a380000000568656c6c6f')
        self.assertEqual(decode_oson(Resp), 'hello')

    def test_ub4_tree_size_count_and_offsets(self):
        # flag 0x1000 -> ub4 tree_size; array node tag 0xf0 -> ub4 count (0x10)
        # + ub4 value-offsets (0x20). A 2-element array [null, null].
        Resp = bytes.fromhex(
            'ff4a5a0130060000000000000f0000'  # hdr: flags 3006, ub4 tree_size=15
            'f0000000020000000d0000000e3030'
        )  # array: 0xf0, count4=2, offs4 13/14, 30 30
        self.assertEqual(decode_oson(Resp), [None, None])


if __name__ == '__main__':
    unittest.main()
