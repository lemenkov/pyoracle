# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Exercise the capture-replay harness (#439).

Proves a captured server response — pasted from ``hexdump -C`` output into a
``tests/captures/*.hexdump`` file — can be pushed through seerdb's packet
framing offline, so future decode regressions can be pinned from a Wireshark /
tcpdump capture with no server. The seed capture is a real UROWID fetch that
ends in ORA-01403 (adopted as a capture fact from the go-ora driver, MIT).
"""

import unittest

from replay import ReplaySocket, load_capture, parse_hexdump

from seerdb.common.tns import assemble_packet, decode_packet
from seerdb.common.tns_consts import TNS_DATA


class TestParseHexdump(unittest.TestCase):
    def test_extracts_bytes_ignoring_offset_and_gutter(self):
        dump = '00000000  41 42 43 44  |ABCD|\n00000004  45  |E|'
        self.assertEqual(parse_hexdump(dump), b'ABCDE')

    def test_skips_comments_and_blank_lines(self):
        dump = '# a captured response\n\n00000000  01 02 03  |...|\n\n# trailing note'
        self.assertEqual(parse_hexdump(dump), b'\x01\x02\x03')

    def test_offset_only_line_yields_nothing(self):
        # A line with no byte tokens (short final gutter) contributes nothing.
        self.assertEqual(parse_hexdump('00000000  |.|'), b'')


class TestReplaySocket(unittest.TestCase):
    def test_hands_out_bytes_then_eof(self):
        sock = ReplaySocket(b'hello world')
        self.assertEqual(sock.recv(5), b'hello')
        self.assertEqual(sock.recv(100), b' world')
        self.assertEqual(sock.recv(100), b'')  # EOF once drained

    def test_send_is_discarded(self):
        sock = ReplaySocket(b'')
        self.assertEqual(sock.send(b'ignored'), 7)
        self.assertIsNone(sock.sendall(b'ignored'))


class TestUrowidCaptureReplay(unittest.TestCase):
    # The seed capture is a single large-framed (4-byte length) TNS_DATA packet:
    # a UROWID column fetch whose result set ends in ORA-01403.
    _CAPTURE = load_capture('urowid_ora01403.hexdump')

    def test_capture_is_one_data_packet_of_the_declared_length(self):
        # The 4-byte header length matches the captured byte count exactly.
        declared = int.from_bytes(self._CAPTURE[:4], 'big')
        self.assertEqual(declared, len(self._CAPTURE))
        flag, packet_type, body, rest = assemble_packet(self._CAPTURE, 8192, True)
        self.assertTrue(flag)
        self.assertEqual(packet_type, TNS_DATA)
        self.assertEqual(len(body), declared - 10)  # 8-byte header + 2 data flags
        self.assertEqual(rest, b'')  # exactly one packet, nothing trailing

    def test_framed_body_preserves_the_ttc_content(self):
        # The framed body carries the describe column name and the terminating
        # ORA-01403 error text intact — the wire content a decoder would read.
        (_flag, _type, body, _rest) = assemble_packet(self._CAPTURE, 8192, True)
        self.assertIn(b'COL_UROWID', body)
        self.assertIn(b'ORA-01403: no data found', body)


class TestUrowidCaptureDecode(unittest.TestCase):
    # The capture-replay harness end to end (#439): frame the captured packet,
    # then run it through the TTC token decoder and check the values a live
    # fetch would have yielded — a describe, the UROWID rows, and the ORA-01403.
    _CAPTURE = load_capture('urowid_ora01403.hexdump')
    _FIELD_VERSION = 11  # the TTC field version this response was captured at

    def _decode(self) -> tuple:
        (_flag, _type, body, _rest) = assemble_packet(self._CAPTURE, 8192, True)
        # A fresh describe-led response decodes from the empty seed context; the
        # positional result is decode_packet's contract (err_code, describe,
        # rows, err_msg at indices 1/3/4/5).
        return decode_packet(body, (None, None, []), self._FIELD_VERSION)

    def test_describe_identifies_the_urowid_column(self):
        column = self._decode()[3][1][0]
        self.assertEqual(column['column_name'], b'COL_UROWID')
        self.assertEqual(column['data_type'], 208)  # UROWID

    def test_decodes_the_urowid_rows(self):
        rows = self._decode()[4]
        self.assertEqual(len(rows), 12)
        # The first row's UROWID and a NULL UROWID mid-set both decode.
        self.assertEqual(rows[0], ['*AAAAegABAAAAAQAK'])
        self.assertIsNone(rows[3][0])
        for (value,) in rows:
            if value is not None:
                # Oracle's UROWID text is the '*'-prefixed base64 physical rowid.
                self.assertTrue(value.startswith('*'))

    def test_terminating_error_is_ora_01403(self):
        result = self._decode()
        self.assertEqual(result[1], 1403)
        self.assertEqual(result[5], 'ORA-01403: no data found')


if __name__ == '__main__':
    unittest.main()
