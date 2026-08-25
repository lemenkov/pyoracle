# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""TNS_REFUSE handling: connect() must surface the listener's ORA error.

Before this, a refused login (e.g. ORA-12514 when the requested service is not
registered — as happens briefly after a listener restart) left a half-open
connection whose failure only showed up, opaquely, as "connection is closed" on
the next call. handle_login now raises the refusal's ORA error at connect time.
The refuse body below is a real capture from an Oracle 23.x listener.
"""

import asyncio
import unittest

from seerdb.client.aconnection import AsyncOracleConnect
from seerdb.client.connection import OracleConnect, _parse_refuse_code
from seerdb.common.exceptions import DatabaseError, OperationalError
from seerdb.common.tns_consts import TNS_REFUSE

# Real TNS_REFUSE body: 1-byte user reason, 1-byte system reason, ub2 length,
# then the ASCII descriptor carrying ERR=/CODE=.
REFUSE_12514 = (
    b'\x22\x00\x00\x53'
    b'(DESCRIPTION=(TMP=)(VSNNUM=0)(ERR=12514)'
    b'(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))'
)


class TestParseRefuseCode(unittest.TestCase):
    def test_extracts_code(self):
        self.assertEqual(_parse_refuse_code(REFUSE_12514), 12514)

    def test_prefers_first_nonzero(self):
        # ERR=0 with the real code later in CODE= must not resolve to 0.
        Body = b'(DESCRIPTION=(ERR=0)(ERROR_STACK=(ERROR=(CODE=12520))))'
        self.assertEqual(_parse_refuse_code(Body), 12520)

    def test_no_code_returns_none(self):
        self.assertIsNone(_parse_refuse_code(b'(DESCRIPTION=(TMP=))'))


class TestRefuseRaises(unittest.TestCase):
    def _conn(self, packet):
        Conn = OracleConnect()
        Conn.recv = lambda a, b: (TNS_REFUSE, packet)
        Conn.disconnect = lambda: None
        return Conn

    def test_refuse_raises_ora_code(self):
        with self.assertRaises(DatabaseError) as Ctx:
            self._conn(REFUSE_12514).handle_login()
        self.assertEqual(Ctx.exception.code, 12514)
        self.assertIn('12514', str(Ctx.exception))

    def test_refuse_without_code_raises_operational(self):
        with self.assertRaises(OperationalError):
            self._conn(b'(DESCRIPTION=(TMP=))').handle_login()

    def test_async_refuse_raises_ora_code(self):
        async def run():
            Conn = AsyncOracleConnect()

            async def _recv(a, b):
                return (TNS_REFUSE, REFUSE_12514)

            async def _disc():
                return None

            Conn.recv = _recv
            Conn.disconnect = _disc
            await Conn.handle_login()

        with self.assertRaises(DatabaseError) as Ctx:
            asyncio.run(run())
        self.assertEqual(Ctx.exception.code, 12514)


if __name__ == '__main__':
    unittest.main()
