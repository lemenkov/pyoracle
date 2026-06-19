# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Tests for query cancellation / call_timeout (#123, #144).
#
# The break has two paths (matching python-oracledb): an out-of-band urgent byte
# when the server advertised attention support (CAN_RECV_ATTENTION -> conn.
# _supports_oob), else an in-band INTERRUPT marker packet (TNS_MARKER, body
# 01 00 03). The in-band path works on any server over any network path; the
# OOB-only break from #123 silently did nothing where OOB isn't advertised /
# carried. None of the local Free/XE testbeds advertise OOB, so the in-band
# interruption -> ORA-01013 and connection reuse are what's verified live on
# 10g/11g/21c/23ai; these cover the client wiring for both paths.

import socket
import unittest

from oracle.connection import OracleConnect
from oracle.tns_consts import TNS_MARKER, TNS_MARKER_TYPE_INTERRUPT


class _FakeSock:
    def __init__(self):
        self.oob = []
        self.normal = []

    def send(self, data, flags=0):
        if flags & socket.MSG_OOB:
            self.oob.append(bytes(data))
        else:
            self.normal.append(bytes(data))
        return len(data)


def _conn():
    return OracleConnect(host="x", port=1, user="u", password="p")


class TestCallTimeout(unittest.TestCase):
    def test_setter_clamps(self):
        c = _conn()
        self.assertEqual(c.call_timeout, 0)
        c.call_timeout = 5000
        self.assertEqual(c.call_timeout, 5000)
        c.call_timeout = -10
        self.assertEqual(c.call_timeout, 0)
        c.call_timeout = None
        self.assertEqual(c.call_timeout, 0)


class TestBreak(unittest.TestCase):
    def test_cancel_sends_inband_marker_by_default(self):
        # no OOB advertised -> in-band INTERRUPT marker packet
        c = _conn()
        c.sock = _FakeSock()
        self.assertFalse(c._supports_oob)
        c.cancel()
        self.assertTrue(c._break_in_progress)
        self.assertEqual(c.sock.oob, [])
        self.assertEqual(len(c.sock.normal), 1)
        pkt = c.sock.normal[0]
        self.assertEqual(pkt[4], TNS_MARKER)             # packet type byte
        self.assertEqual(pkt[-3:],
                         bytes([1, 0, TNS_MARKER_TYPE_INTERRUPT]))

    def test_cancel_sends_oob_when_supported(self):
        # server advertised CAN_RECV_ATTENTION -> the OOB urgent byte
        c = _conn()
        c.sock = _FakeSock()
        c._supports_oob = True
        c.cancel()
        self.assertEqual(c.sock.oob, [b"!"])
        self.assertEqual(c.sock.normal, [])

    def test_break_is_idempotent(self):
        c = _conn()
        c.sock = _FakeSock()
        c._break_in_progress = True
        c._send_break()
        self.assertEqual(c.sock.normal, [])              # in progress -> no-op

    def test_break_without_socket_is_noop(self):
        c = _conn()
        c.sock = None
        c._send_break()                                  # must not raise
        self.assertFalse(c._break_in_progress)

    def test_on_call_timeout_flags_and_breaks(self):
        c = _conn()
        c.sock = _FakeSock()
        c._on_call_timeout()
        self.assertTrue(c._timed_out)
        self.assertTrue(c._break_in_progress)
        self.assertEqual(len(c.sock.normal), 1)
        self.assertEqual(c.sock.normal[0][-3:],
                         bytes([1, 0, TNS_MARKER_TYPE_INTERRUPT]))


if __name__ == "__main__":
    unittest.main()
