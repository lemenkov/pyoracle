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

from seerdb.common.tns import assemble_packet
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


if __name__ == '__main__':
    unittest.main()
