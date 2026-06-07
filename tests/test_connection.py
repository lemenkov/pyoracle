# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import unittest
from oracle.connection import OracleConnect
from oracle.exceptions import DatabaseError


class TestConnection(unittest.TestCase):

    def test_empty_credentials_rejected(self):
        # Connecting with the default empty username/password must not silently
        # "succeed". The server rejects the logon with an auth-error OER, which
        # now surfaces as a DatabaseError (ORA-01017) instead of being swallowed
        # — and crucially no longer hangs the handshake. Needs a reachable
        # listener on localhost:1521; an unreachable one raises OSError instead.
        con = OracleConnect()
        with self.assertRaises((DatabaseError, OSError)):
            con.connect()
