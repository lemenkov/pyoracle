# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Sans-io wire dialects for the pre-10g Oracle tiers (#369).

The pre-10g tiers (9i / fv2, and 8i) speak wire *dialects* that are hard forks of
the modern 10g→23ai protocol — different TTC function codes, request framing and
describe/row shapes — so they can't be folded into the modern encoders behind
another ``if field_version <`` branch. Historically each became a parallel set of
``_fv2_* `` / ``_8i_*`` methods on both :class:`OracleConnect` **and**
:class:`AsyncOracleConnect` — a near-verbatim ``await``-sprinkled duplicate.

This module removes both the 3-way dispatch ladder and the sync/async duplication
at once. A :class:`Dialect` is written **once** as *sans-io* generators: each
method yields :class:`Send` / :data:`RECV` intents instead of touching a socket,
and the connection drives it with a tiny sync or async loop (``_drive`` on each
connection class). The wire codecs (``encode_o7_*`` / ``decode_fv2_*`` …) are
already colorless byte-in/byte-out functions, so the dialect just sequences them.

A generator method that yields ``Send(data)`` means "send this as a TNS_DATA
packet"; ``yield RECV`` means "give me the next data packet" and evaluates to the
``(type, packet)`` tuple (or ``False`` on a closed connection), exactly as
``_next_data_packet`` returns. Sibling steps compose with ``yield from``; ORA
errors are raised inline and propagate through the driver.
"""

from __future__ import annotations

from typing import Protocol

from seerdb.common.tns import (
    decode_fv2_block_out,
    decode_fv2_describe,
    decode_fv2_dml_response,
    decode_fv2_exec_response,
    decode_fv2_lob_chunks,
    decode_fv2_lob_getlen,
    decode_fv2_oer_error,
    decode_fv2_opened_locator,
    encode_o7_bfile_close,
    encode_o7_bfile_open,
    encode_o7_block,
    encode_o7_close,
    encode_o7_describe,
    encode_o7_exec,
    encode_o7_lob_getlen,
    encode_o7_lob_read,
    encode_o7_open,
    encode_o7_parse,
    encode_tokens_rxd,
)


class Send:
    """A wire intent: write ``data`` as a single TNS_DATA packet."""

    __slots__ = ('data',)

    def __init__(self, data: bytes) -> None:
        self.data = data


# The "receive the next data packet" intent. A bare sentinel — the driver returns
# ``_next_data_packet()``'s result (``(type, packet)`` or ``False``) back into the
# generator at the ``yield RECV`` site.
RECV = object()


def fv2_raise_for_error(packet: bytes) -> None:
    """Raise the server's error if ``packet`` is a 9i OER carrying a real ORA
    code (not success / end-of-fetch), so a parse-time failure surfaces as its
    true code + message instead of a downstream desync (#102). Colorless — shared
    by the fv2 dialect and the (still-inline) 8i methods."""
    (err_code, message) = decode_fv2_oer_error(packet)
    if err_code and err_code not in (0, 1403):
        from seerdb.common.exceptions import from_ora_code

        raise from_ora_code(err_code)(message or f'ORA-{err_code:05d}', code=err_code)


class Dialect(Protocol):
    """A pre-10g wire dialect as sans-io generators. Each ``execute_*`` yields
    :class:`Send` / :data:`RECV` intents and returns the same 9-tuple the modern
    execute path produces, so ``_drain_cursor`` and the cursor are unchanged."""

    def capabilities(self) -> frozenset[str]: ...
    def execute_query(self, sql: str, bind: list | None): ...
    def execute_dml(self, sql: str, bind: list | None): ...
    def execute_block(self, sql: str, bind: list | None): ...


# Capability tokens a dialect advertises via capabilities() — one honest place for
# "does this tier do array DML / JSON / …" instead of ad-hoc NotSupportedErrors.
CAP_QUERY = 'query'
CAP_DML = 'dml'
CAP_BLOCK = 'block'
CAP_LOB = 'lob'
CAP_ARRAY_DML = 'array_dml'


class Fv2Dialect:
    """Oracle 9i (TTC field version 2) — the four-call TTI_ALL7 dialect (#102,
    PROTOCOL.md §19). Sans-io: driven by ``OracleConnect._drive`` (sync) or
    ``AsyncOracleConnect._drive`` (async)."""

    def capabilities(self) -> frozenset[str]:
        # 9i does query / DML / PL/SQL blocks / LOB, but NOT array DML
        # (executemany) — that's a 10g+ feature.
        return frozenset({CAP_QUERY, CAP_DML, CAP_BLOCK, CAP_LOB})

    def execute_query(self, sql: str, bind: list | None = None):
        # 9i SELECT: the four-call TTI_ALL7 sequence (parse, describe, execute +
        # fetch, close). Returns the same tuple shape as a normal execute response
        # so the cursor / _drain_cursor machinery is unchanged.
        yield Send(encode_o7_open(0))  # allocate a server cursor
        yield RECV  # OOPEN RPA (cursor id)
        yield Send(encode_o7_parse(0, sql, bind))
        resp = yield RECV  # parse RPA ack — or an OER
        if resp is not False:  # surface a parse error (e.g. ORA-00942)
            fv2_raise_for_error(resp[1])
        yield Send(encode_o7_describe(0))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i describe')
        columns = decode_fv2_describe(resp[1])
        # Execute, then fetch in batches: each batch re-sends the same exec+fetch
        # TTI_ALL7; the server continues the cursor and ends with ORA-01403 (#99).
        # A batch with no rows also terminates the loop so a malformed response
        # can't spin forever.
        all_rows: list = []
        err_code = 0
        while True:
            yield Send(encode_o7_exec(0, columns))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i fetch')
            (rows, err_code) = decode_fv2_exec_response(resp[1], columns)
            all_rows.extend(rows)
            if err_code == 1403 or not rows:
                break
        # Resolve LOB cells while the cursor is still open (JDBC does the same):
        # decode_fv2_exec_response left LOB objects in the rows; replace each with
        # its content.
        yield from self.resolve_lobs(all_rows, columns)
        yield Send(encode_o7_close(0))
        yield RECV  # close STA
        _raise_terminal(err_code)
        # call_status 0 + ora_code 0 => _drain_cursor won't issue TTI_FETCHes.
        return (0, 0, 0, (len(all_rows), columns), all_rows, None, None, [], None)

    def execute_dml(self, sql: str, bind: list | None = None):
        # 9i DML over TTI_ALL7 (#101): OOPEN, then a single parse that also
        # executes (option 02 80 21) — no describe/fetch. The affected-row count
        # comes back in the response OER. (Autocommit is applied by the caller.)
        yield Send(encode_o7_open(0))
        yield RECV  # OOPEN RPA
        yield Send(encode_o7_parse(0, sql, bind))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i DML')
        fv2_raise_for_error(resp[1])  # e.g. ORA-00942 / constraint
        (row_count, err_code) = decode_fv2_dml_response(resp[1])
        yield Send(encode_o7_close(0))
        yield RECV  # close STA
        _raise_terminal(err_code)
        return (0, 0, 0, (row_count, None), [], None, None, [], None)

    def execute_block(self, sql: str, bind: list | None = None):
        # Anonymous PL/SQL block over the fv2 TTI_ALL7 block path (#102, PROTOCOL
        # §19.6 / §19.7). OOPEN, then encode_o7_block parse-executes the block with
        # an OAC per bind (no inline values). The server replies with a bind
        # prompt; the client sends the INPUT values (IN + IN OUT, position order)
        # as a standalone RXD, and the reply carries any OUT / IN OUT return values
        # (an RXD before the RPA + OER). A pure-OUT block packs prompt + returns +
        # status in one packet and expects no input; a no-bind block returns the
        # RPA + OER directly. OUT values ride back as an {out_positions, out_values}
        # record the cursor's _assign_out_binds decodes into the Var objects.
        from seerdb.common.datatypes import Var

        bind = bind or []
        # IN + IN OUT binds carry an input value; every Var is an OUT (IN OUT = a
        # Var with has_value set).
        input_values = [
            (b._value if isinstance(b, Var) else b)
            for b in bind
            if not isinstance(b, Var) or b.has_value
        ]
        out_positions = [i for i, b in enumerate(bind) if isinstance(b, Var)]
        yield Send(encode_o7_open(0))
        yield RECV  # OOPEN RPA
        yield Send(encode_o7_block(0, sql, bind))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i PL/SQL block')
        packet = resp[1]
        if input_values:
            # `packet` is the bind prompt (or an OER on a compile error). Send the
            # input values; the reply carries OUT values + RPA + OER.
            fv2_raise_for_error(packet)
            yield Send(encode_tokens_rxd(input_values, b''))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i PL/SQL bind send')
            packet = resp[1]
        fv2_raise_for_error(packet)  # runtime error (ORA-06512 …)
        (out_values, row_count, err_code) = decode_fv2_block_out(
            packet, len(out_positions)
        )
        yield Send(encode_o7_close(0))
        yield RECV  # close STA
        _raise_terminal(err_code)
        if out_positions:
            record = {'out_positions': out_positions, 'out_values': out_values}
            return (0, 0, 0, (None, None), [record], None, None, [], None)
        return (0, 0, 0, (row_count, None), [], None, None, [], None)

    def resolve_lobs(self, rows: list, columns: list):
        # Replace LOB objects left by decode_fv2_exec_response with their content,
        # in place, by round-tripping each locator (#102). Done while the 9i cursor
        # is still open.
        from seerdb.common.lob import LOB
        from seerdb.common.types import decode_fv2_lob

        for row in rows:
            for i, val in enumerate(row):
                if isinstance(val, LOB):
                    if val.data_type == 114:  # BFILE: open / read / close
                        content = yield from self.bfile_read(val.raw)
                    else:  # CLOB / BLOB: GETLEN + READ
                        content = yield from self.lob_read(val.raw)
                    row[i] = decode_fv2_lob(
                        columns[i].get('data_type'),
                        content,
                        columns[i].get('charset') or 0,
                    )

    def lob_read(self, locator: bytes):
        # 9i CLOB/BLOB content read: the two-call TTI_LOBOPS GETLEN + READ
        # (PROTOCOL.md §19.5). Returns raw bytes (CLOB decoding happens in the
        # caller with the column charset). An empty LOB (amount 0) reads nothing.
        yield Send(encode_o7_lob_getlen(0, locator))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i LOB GETLEN')
        amount = decode_fv2_lob_getlen(resp[1])
        if amount <= 0:
            return b''
        yield Send(encode_o7_lob_read(0, locator, amount))
        return (yield from self.read_lob_content())

    def bfile_read(self, locator: bytes):
        # 9i BFILE read: FILE_OPEN → GETLEN → READ → FILE_CLOSE over TTI_LOBOPS
        # (PROTOCOL §19.8). FILE_OPEN returns an *updated* locator (open flag set);
        # GETLEN/READ/CLOSE must use that one. The FILE_CLOSE runs in a finally so
        # an opened file is always closed even if the read fails.
        yield Send(encode_o7_bfile_open(0, locator))
        resp = yield RECV
        if resp is False:
            raise Exception('Connection closed during 9i BFILE FILE_OPEN')
        fv2_raise_for_error(resp[1])  # e.g. ORA-22285
        opened = decode_fv2_opened_locator(resp[1])
        if opened is None:
            raise Exception('Unexpected 9i BFILE FILE_OPEN reply', resp[1][:8].hex())
        try:
            yield Send(encode_o7_lob_getlen(0, opened))
            resp = yield RECV
            if resp is False:
                raise Exception('Connection closed during 9i BFILE GETLEN')
            amount = decode_fv2_lob_getlen(resp[1])
            if amount <= 0:
                return b''
            yield Send(encode_o7_lob_read(0, opened, amount))
            return (yield from self.read_lob_content())
        finally:
            yield Send(encode_o7_bfile_close(0, opened))
            yield RECV  # drain FILE_CLOSE RPA + OER

    def read_lob_content(self):
        # Read a 9i TTI_LOBOPS READ reply by accumulating packets and re-parsing
        # with decode_fv2_lob_chunks until it reports the zero-length terminator.
        # The fv2 reply carries no OER call-status, so that terminator (not an OER)
        # is the stop signal. (#102)
        data = b''
        while True:
            received = yield RECV
            if received is False:
                raise Exception('Connection closed during 9i LOB READ')
            data += received[1]
            (content, complete) = decode_fv2_lob_chunks(data)
            if complete:
                return content


def _raise_terminal(err_code: int) -> None:
    # Raise the ORA error carried by a terminal status (not success / 1403).
    if err_code and err_code not in (0, 1403):
        from seerdb.common.exceptions import from_ora_code

        raise from_ora_code(err_code)(f'ORA-{err_code:05d}', code=err_code)
