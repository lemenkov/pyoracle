# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Offline tests for DML RETURNING ... INTO (#120): the return-bind detection,
# the out-bind return-data decode, and the per-Var assignment.
#
# The wire bytes mirror what a live server sends (TTI_RXD carrying, per return
# bind, a ub4 row count then each row's length-prefixed value + an sb4
# truncation length), verified against 10g/11g/21c/23ai.

import unittest

from seerdb.client.connection import OracleConnect
from seerdb.client.cursor import _assign_return_binds
from seerdb.common.datatypes import Var
from seerdb.common.exceptions import InterfaceError
from seerdb.common.sqltext import returning_bind_positions
from seerdb.common.tns import (
    FLUSH_OUT_BINDS,
    MAX_FLUSH_OUT_BINDS,
    decode_packet,
    decode_token_rxd,
    encode_dictionary_exec,
    set_decode_return_binds,
)
from seerdb.common.tns_consts import (
    FIELD_VERSION_11_2,
    TNS_DATA,
    TTI_FOB,
    TTI_STA,
    VERSION_11_2_0_2,
)


class TestReturningDetection(unittest.TestCase):
    def test_insert_returning_into(self):
        sql = 'INSERT INTO t VALUES (:1, :2) RETURNING id INTO :3'
        self.assertEqual(returning_bind_positions(sql, 3), frozenset({2}))

    def test_multiple_return_binds(self):
        sql = 'UPDATE t SET n=:1 WHERE id=:2 RETURNING id, n INTO :3, :4'
        self.assertEqual(returning_bind_positions(sql, 4), frozenset({2, 3}))

    def test_all_return_no_input(self):
        sql = "INSERT INTO t VALUES (1, 'x') RETURNING name INTO :1"
        self.assertEqual(returning_bind_positions(sql, 1), frozenset({0}))

    def test_not_returning(self):
        self.assertEqual(
            returning_bind_positions('INSERT INTO t VALUES (:1)', 1), frozenset()
        )
        # the INSERT's own INTO must not be mistaken for a RETURNING INTO
        self.assertEqual(
            returning_bind_positions('INSERT INTO t (a) VALUES (:1)', 1), frozenset()
        )

    def test_returning_in_string_literal_ignored(self):
        sql = "UPDATE t SET note = 'returning into x' WHERE id = :1"
        self.assertEqual(returning_bind_positions(sql, 1), frozenset())


# A TTI_RXD (0x07) carrying return data for two binds: NUMBER 42 and VARCHAR
# 'hi', one row each, then a TTI_STA to end the response.
_RXD_TWO = (
    bytes([7])
    + bytes.fromhex('0101')
    + bytes.fromhex('02')
    + bytes.fromhex('c12b')
    + bytes.fromhex('00')
    + bytes.fromhex('0101')
    + bytes.fromhex('02')
    + b'hi'
    + bytes.fromhex('00')
    + bytes([TTI_STA])
)

# One NUMBER bind, two rows (multi-row DML RETURNING): 42 then 43.
_RXD_MULTI = (
    bytes([7])
    + bytes.fromhex('0102')  # num_rows = 2
    + bytes.fromhex('02')
    + bytes.fromhex('c12b')
    + bytes.fromhex('00')
    + bytes.fromhex('02')
    + bytes.fromhex('c12c')
    + bytes.fromhex('00')
    + bytes([TTI_STA])
)


class TestReturningDecode(unittest.TestCase):
    def tearDown(self):
        set_decode_return_binds(None)

    def _decode(self, data, positions):
        set_decode_return_binds(positions)
        (Done, Acc) = decode_token_rxd(data, (None, None, []))
        self.assertTrue(Done)
        return Acc[2][0]  # the return record

    def test_two_binds_single_row(self):
        rec = self._decode(_RXD_TWO, [0, 1])
        self.assertEqual(rec['return_positions'], [0, 1])
        self.assertEqual(rec['return_values'][0], [b'\xc1\x2b'])
        self.assertEqual(rec['return_values'][1], [b'hi'])

    def test_multi_row(self):
        rec = self._decode(_RXD_MULTI, [0])
        self.assertEqual(rec['return_values'][0], [b'\xc1\x2b', b'\xc1\x2c'])

    def test_assign_decodes_by_var_type(self):
        rec = self._decode(_RXD_TWO, [1, 2])  # binds at positions 1 and 2
        result = (None, None, None, None, [rec])
        bind = ['input', Var(int), Var(str)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[1].getvalue(), [42])
        self.assertEqual(bind[2].getvalue(), ['hi'])


def _exec_bytes(bind, batch, return_binds):
    """The wire bytes of one array execute of a RETURNING statement."""
    return encode_dictionary_exec(
        {
            'seq': 3,
            'query': {
                'type': 'change',
                'auto': 0,
                'fetch': 0,
                'server_version': VERSION_11_2_0_2,
                'cursor': 0,
                'query': 'insert into t (v) values (:1) returning id into :2',
                'bind': bind,
                'batch': batch,
                'def': [],
                'batcherrors': False,
                'arraydmlrowcounts': False,
                'return_binds': return_binds,
                'scrollable': False,
                'scroll': None,
            },
        }
    )


class TestArrayReturningEncode(unittest.TestCase):
    """An array execute must not send a value for a server-filled bind (#687).

    Every bind is described once in the type block, but a `RETURNING ... INTO`
    out-bind is filled by the server from the rows each iteration affected. Its
    value therefore belongs in no iteration's row data. Sending one shifted
    everything after it, and the server rejected the whole call as a malformed
    packet and dropped the connection.
    """

    def _cost_of_the_receiver(self, iterations):
        """How many more bytes the receiver adds over the same batch without it.

        The receiver is described once, so this is one descriptor's worth and
        must not depend on how many iterations there are. If it did, the
        receiver would be travelling in the row data.
        """
        receiver = Var(int)
        inputs = [[f'v{n}'] for n in range(iterations)]
        rows = [row + [receiver] for row in inputs]
        with_receiver = _exec_bytes(rows[0], rows[1:], frozenset({1}))
        without = _exec_bytes(inputs[0], inputs[1:], None)
        return len(with_receiver) - len(without)

    def test_return_bind_costs_the_same_at_any_batch_size(self):
        self.assertEqual(self._cost_of_the_receiver(2), self._cost_of_the_receiver(8))

    def test_return_bind_value_absent_from_every_iteration(self):
        receiver = Var(int)
        rows = [['a', receiver], ['bb', receiver], ['ccc', receiver]]
        encoded = _exec_bytes(rows[0], rows[1:], frozenset({1}))
        # Each iteration contributes exactly its own input value, and nothing
        # for the receiver.
        for value in (b'a', b'bb', b'ccc'):
            self.assertIn(value, encoded)
        self.assertEqual(encoded.count(b'ccc'), 1)

    def test_matches_the_same_batch_without_the_receiver(self):
        """The row data is byte-identical to a batch of the inputs alone.

        The two differ only in the type block, which describes the extra bind.
        Comparing the tail past the longest shared prefix isolates the row data,
        which is where the bug was.
        """
        receiver = Var(int)
        with_receiver = _exec_bytes(
            ['a', receiver], [['bb', receiver], ['ccc', receiver]], frozenset({1})
        )
        # A three-row batch of the inputs only, no RETURNING involved.
        inputs_only = _exec_bytes(['a'], [['bb'], ['ccc']], None)
        self.assertTrue(with_receiver.endswith(inputs_only[-len(b'ccc') - 8 :]))

    def test_without_return_binds_every_bind_still_travels(self):
        """A plain array execute is unchanged."""
        encoded = _exec_bytes(['a', 'x'], [['bb', 'y']], None)
        for value in (b'a', b'x', b'bb', b'y'):
            self.assertIn(value, encoded)


class TestArrayReturningAssign(unittest.TestCase):
    """Each iteration returns its own rows, and all of them must be kept."""

    def tearDown(self):
        set_decode_return_binds(None)

    def _record(self, values):
        return {'return_positions': [0], 'return_values': [values]}

    def test_per_iteration_values(self):
        result = (
            None,
            None,
            None,
            None,
            [self._record([b'\xc1\x02']), self._record([b'\xc1\x03'])],
        )
        bind = [Var(int)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[0].getvalue(0), [1])
        self.assertEqual(bind[0].getvalue(1), [2])
        # No argument keeps reading the first iteration, as before.
        self.assertEqual(bind[0].getvalue(), [1])

    def test_iteration_returning_several_rows(self):
        """An UPDATE can affect many rows in a single iteration."""
        result = (
            None,
            None,
            None,
            None,
            [self._record([b'\xc1\x02', b'\xc1\x03']), self._record([b'\xc1\x04'])],
        )
        bind = [Var(int)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[0].getvalue(0), [1, 2])
        self.assertEqual(bind[0].getvalue(1), [3])

    def test_single_iteration_keeps_the_flat_shape(self):
        """One execute has one iteration, so `pos` is ignored."""
        result = (None, None, None, None, [self._record([b'\xc1\x02'])])
        bind = [Var(int)]
        _assign_return_binds(bind, result)
        self.assertEqual(bind[0].getvalue(), [1])
        self.assertEqual(bind[0].getvalue(4), [1])


class TestFlushOutBindsRequest(unittest.TestCase):
    """The server asks before it answers, when a RETURNING statement fails (#697).

    Its whole reply is one byte -- the TTI_FOB token, nothing else -- and it then
    waits. The real error only arrives once the client has echoed the token back.
    Reading that packet as if it were a result abandoned the response mid-stream
    and left the connection unusable: the next statement on it came back
    ORA-03137, a protocol violation, because the server was still waiting.
    """

    def test_a_bare_fob_packet_decodes_to_the_marker(self):
        (Done, Marker) = decode_packet(bytes([TTI_FOB]), (None, None, []))
        self.assertIs(Done, False)
        self.assertEqual((Done, Marker), FLUSH_OUT_BINDS)

    def test_the_marker_is_not_mistaken_for_a_result(self):
        # It has to be distinguishable from anything a caller would keep, or the
        # request gets handed on as an answer -- which is how it surfaced, as
        # "unexpected wire response: (False, 'fob')".
        (Done, _Acc) = decode_packet(bytes([TTI_STA]), (None, None, []))
        self.assertNotEqual((Done, _Acc), FLUSH_OUT_BINDS)


class TestFlushOutBindsAcknowledged(unittest.TestCase):
    """The connection answers the request and reads on, rather than giving up."""

    class _Wire:
        """A connection stripped to what _handle_response touches."""

        field_version = FIELD_VERSION_11_2

        def __init__(self, packets):
            self._packets = list(packets)
            self.sent = []

        def _next_data_packet(self, _a, _b):
            return (TNS_DATA, self._packets.pop(0)) if self._packets else False

        def send(self, _type, data):
            self.sent.append(data)

    def _read(self, packets):
        wire = self._Wire(packets)
        result = OracleConnect._handle_response(wire)
        return wire, result

    def test_the_token_is_echoed_back_and_the_answer_read(self):
        wire, result = self._read([bytes([TTI_FOB]), bytes([TTI_STA])])
        # Exactly the one byte the server sent, straight back.
        self.assertEqual(wire.sent, [bytes([TTI_FOB])])
        # And the response behind it is what the caller receives.
        self.assertIsNot(result, FLUSH_OUT_BINDS)

    def test_an_ordinary_response_sends_nothing(self):
        wire, _ = self._read([bytes([TTI_STA])])
        self.assertEqual(wire.sent, [])

    def test_a_server_that_never_stops_asking_ends_the_call(self):
        # A cap, not a fix for anything real: one request is what a server sends.
        # Without it a broken server would spin here forever.
        with self.assertRaises(InterfaceError):
            self._read([bytes([TTI_FOB])] * (MAX_FLUSH_OUT_BINDS + 1))


if __name__ == '__main__':
    unittest.main()


class TestReturningIsRefusedBelow10g(unittest.TestCase):
    """RETURNING ... INTO needs the 10g+ request form (#716).

    9i refuses the clause for this client type and 8i drops the connection on
    a failure, so the driver says so before any I/O. A connection whose version
    is not yet known is not refused.
    """

    def _check(self, version):
        import types

        from seerdb.client.cursor import _check_returning_support

        conn = (
            types.SimpleNamespace(field_version=version)
            if version
            else types.SimpleNamespace()
        )
        _check_returning_support(conn, frozenset({1}))

    def test_9i_is_refused(self):
        from seerdb.common.exceptions import NotSupportedError
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        with self.assertRaises(NotSupportedError):
            self._check(FIELD_VERSION_9_2)

    def test_10g_and_later_are_not(self):
        from seerdb.common.tns_consts import FIELD_VERSION_10_2, FIELD_VERSION_11_2

        self._check(FIELD_VERSION_10_2)
        self._check(FIELD_VERSION_11_2)

    def test_an_unknown_version_is_not_refused(self):
        self._check(None)

    def test_a_statement_without_the_clause_is_never_refused(self):
        import types

        from seerdb.client.cursor import _check_returning_support
        from seerdb.common.tns_consts import FIELD_VERSION_9_2

        _check_returning_support(
            types.SimpleNamespace(field_version=FIELD_VERSION_9_2), frozenset()
        )
