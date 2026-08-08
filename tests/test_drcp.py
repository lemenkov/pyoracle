# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for DRCP / implicit connection pooling (#130): the connect
# descriptor gains (SERVER=POOLED), the connection threads cclass/purity, and
# the response decoder skips the server-side piggyback DRCP sessions carry. The
# live cclass/purity auth round-trip is covered on 21c/23ai.

import unittest

from oracle.connection import OracleConnect
from oracle.tns import decode_packet, encode_dictionary_description
from oracle.tns_consts import PURITY_SELF, TTI_STA, TTI_SVR_PIGGYBACK


def _env(**extra):
    base = {
        'host': 'h',
        'port': 1521,
        'user': 'u',
        'service_name': 'svc',
        'app_name': 'pyoracle',
    }
    base.update(extra)
    return {'env': base}


class TestDescriptor(unittest.TestCase):
    def test_pooled_when_drcp(self):
        self.assertIn(
            b'(SERVER=POOLED)', encode_dictionary_description(_env(cclass='APP'))
        )
        self.assertIn(
            b'(SERVER=POOLED)', encode_dictionary_description(_env(purity=PURITY_SELF))
        )

    def test_no_pooled_otherwise(self):
        self.assertNotIn(b'(SERVER=POOLED)', encode_dictionary_description(_env()))


class TestParams(unittest.TestCase):
    def test_connection_threads_cclass_purity(self):
        c = OracleConnect(
            host='x', port=1, user='u', password='p', cclass='MYAPP', purity=PURITY_SELF
        )
        self.assertEqual(c.cclass, 'MYAPP')
        self.assertEqual(c.purity, PURITY_SELF)
        env = c._make_dict(None)['env']
        self.assertEqual(env['cclass'], 'MYAPP')
        self.assertEqual(env['purity'], PURITY_SELF)


class TestPiggyback(unittest.TestCase):
    def test_skips_sess_ret(self):
        # token 23, opcode 4 (SESS_RET) with all-empty fields, then STA -> the
        # decoder consumes the piggyback and lands on the status token.
        pkt = bytes([TTI_SVR_PIGGYBACK, 4, 0, 0, 0, 0, 0, 0, TTI_STA])
        self.assertEqual(decode_packet(pkt, (None, None, [])), (True, (None, None, [])))

    def test_skips_os_pid_mts(self):
        # opcode 2 (OS_PID_MTS): a ub2 then a length-prefixed pid, then STA
        pkt = bytes([TTI_SVR_PIGGYBACK, 2, 0, 3]) + b'pid' + bytes([TTI_STA])
        self.assertEqual(decode_packet(pkt, (None, None, [])), (True, (None, None, [])))


if __name__ == '__main__':
    unittest.main()
