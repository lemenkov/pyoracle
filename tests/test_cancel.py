# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Structural tests for query cancellation / call_timeout (#123).
#
# NOTE: the actual interruption (an OOB break stopping a running call ->
# ORA-01013 / call-timeout) is NOT exercised here and is UNVERIFIED on the
# local container testbeds: rootless-podman's port-forward does not deliver
# TCP urgent/OOB data, so the break never reaches the server. The protocol is
# implemented per python-oracledb; these tests cover the client-side wiring
# (the break is sent OOB, state latches, call_timeout clamps, idempotency).

import socket
import unittest

from oracle.connection import OracleConnect


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
    def test_cancel_sends_oob(self):
        c = _conn()
        c.sock = _FakeSock()
        c.cancel()
        self.assertTrue(c._break_in_progress)
        self.assertEqual(c.sock.oob, [b"!"])     # OOB only, no in-band residue
        self.assertEqual(c.sock.normal, [])

    def test_break_is_idempotent(self):
        c = _conn()
        c.sock = _FakeSock()
        c._break_in_progress = True
        c._send_break()
        self.assertEqual(c.sock.oob, [])          # already in progress -> no-op

    def test_break_without_socket_is_noop(self):
        c = _conn()
        c.sock = None
        c._send_break()                           # must not raise
        self.assertFalse(c._break_in_progress)

    def test_on_call_timeout_flags_and_breaks(self):
        c = _conn()
        c.sock = _FakeSock()
        c._on_call_timeout()
        self.assertTrue(c._timed_out)
        self.assertTrue(c._break_in_progress)
        self.assertEqual(c.sock.oob, [b"!"])


if __name__ == "__main__":
    unittest.main()
