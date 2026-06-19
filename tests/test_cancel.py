# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Tests for query cancellation / call_timeout (#123, #144).
#
# The break is an in-band INTERRUPT marker packet (#144): an ordinary TNS packet
# (type 12, body 01 00 03), not an OOB urgent byte. This works against a default
# server over any network path (the OOB-only break from #123 silently did
# nothing when the server didn't advertise attention support / the path dropped
# urgent data). The actual interruption -> ORA-01013 and connection reuse after
# the break are verified live on 10g/11g/21c/23ai; these cover the client wiring.

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
    def test_cancel_sends_inband_marker(self):
        c = _conn()
        c.sock = _FakeSock()
        c.cancel()
        self.assertTrue(c._break_in_progress)
        self.assertEqual(c.sock.oob, [])                 # not OOB anymore
        self.assertEqual(len(c.sock.normal), 1)
        pkt = c.sock.normal[0]
        self.assertEqual(pkt[4], TNS_MARKER)             # packet type byte
        # body is the INTERRUPT marker triple
        self.assertEqual(pkt[-3:],
                         bytes([1, 0, TNS_MARKER_TYPE_INTERRUPT]))

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
