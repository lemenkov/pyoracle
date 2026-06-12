# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the OSON (native JSON) decoder.

Each fixture is a real OSON image captured from a live Oracle 21c server for a
known JSON document (see docs/PROTOCOL.md §15). No server is needed to run
these — they pin the decoder against the actual wire format.
"""

import json
import unittest
from decimal import Decimal

from oracle.oson import decode_oson, OsonError


# (label, JSON document, captured OSON image as hex)
FIXTURES = [
    ("null", "null", "ff4a5a010016000130"),
    ("true", "true", "ff4a5a010016000131"),
    ("false", "false", "ff4a5a010016000132"),
    ("num_small", "1", "ff4a5a010016000321c102"),
    ("num_42", "42", "ff4a5a010016000321c12b"),
    ("num_neg", "-7", "ff4a5a0100160004223e5e66"),
    ("num_frac", "3.14", "ff4a5a010016000422c1040f"),
    ("float_e", "1.5e10", "ff4a5a010016000422c60233"),
    ("zero", "0", "ff4a5a01001600022080"),
    ("bigint", "123456789012345", "ff4a5a010016000b3409c802182e445a02182e"),
    ("str_short", '"hi"', "ff4a5a0100160003026869"),
    ("str_world", '"world"', "ff4a5a010016000605776f726c64"),
    ("str_long", '"' + "x" * 50 + '"',
     "ff4a5a01001600343332" + "78" * 50),
    ("str_unicode", '"café—€"',
     "ff4a5a010016000c0b636166c3a9e28094e282ac"),
    ("arr_empty", "[]", "ff4a5a01200600000000020001c000"),
    ("obj_empty", "{}", "ff4a5a012006000000000200018400"),
    ("obj_one", '{"a":1}',
     "ff4a5a012106010002000800002c00000161840101000521c102"),
    ("arr_ints", "[1,2,3]",
     "ff4a5a01200600000000110000c0030008000b000e21c10221c10321c104"),
    ("two_keys", '{"k1":10,"k2":20}',
     "ff4a5a012106020006000e000008c100030000026b31026b32840202010008"
     "000b21c10b21c115"),
    ("obj_mix", '{"hello":"world","n":42,"arr":[1,2,3]}',
     "ff4a5a01210603000c002500001831ab0008000600000568656c6c6f016e03"
     "6172728403030201000b0011001405776f726c6421c12bc003001c001f0022"
     "21c10221c10321c104"),
    ("nested", '{"a":{"b":[true,null,"x"]}}',
     "ff4a5a012106020004001600002ce500000002016101628401010005840102"
     "000ac00300120013001431300178"),
    ("deep_str", '{"msg":"the quick brown fox jumps over"}',
     "ff4a5a01210601000400240000020000036d736784010100051e7468652071"
     "7569636b2062726f776e20666f78206a756d7073206f766572"),
    ("big_arr", json.dumps(list(range(40))),
     "ff4a5a01200600000000c90000c028005200540057005a005d006000630066"
     "0069006c006f007200750078007b007e008100840087008a008d0090009300"
     "960099009c009f00a200a500a800ab00ae00b100b400b700ba00bd00c000c3"
     "00c6208021c10221c10321c10421c10521c10621c10721c10821c10921c10a"
     "21c10b21c10c21c10d21c10e21c10f21c11021c11121c11221c11321c11421"
     "c11521c11621c11721c11821c11921c11a21c11b21c11c21c11d21c11e21c1"
     "1f21c12021c12121c12221c12321c12421c12521c12621c12721c128"),
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
            decode_oson(b"\x00\x01\x02\x03\x04\x05")

    def test_value_types(self):
        # Spot-check the concrete Python types, not just equality.
        d = decode_oson(bytes.fromhex(
            "ff4a5a01210603000c002500001831ab0008000600000568656c6c6f016e03"
            "6172728403030201000b0011001405776f726c6421c12bc003001c001f0022"
            "21c10221c10321c104"))
        self.assertEqual(d["hello"], "world")
        self.assertEqual(d["arr"], [1, 2, 3])
        self.assertIsInstance(d["arr"], list)
        self.assertIsInstance(d, dict)


if __name__ == "__main__":
    unittest.main()
