# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Decoder fuzzing (#165). A buggy or hostile server must never be able to hang
the client or crash it with an out-of-bounds read: a malformed packet should
either decode or raise a clean exception, never loop forever or read past the
buffer. This mutation-fuzzes decode_packet from a corpus of real captured
response packets and asserts exactly that.

The run is bounded and uses a fixed RNG seed so it is fast and reproducible in
CI; a longer ad-hoc sweep lives in tools/fuzz_decoder.py."""

import random
import signal
import unittest

from oracle.tns import decode_packet

# Seed corpus: real captured response packets (token byte first) covering the
# common decoders — DCB (16), RPA (8), PRO (1), RXD (7), OER (4), STA (9), LOB
# (14), markers, end-of-response (29). Mutating around these exercises the
# length/offset/chunk handling that is most at risk of an unbounded loop.
_SEEDS = [
    "101735ebcd3cc510be7fdf53b18448bb2dda787e0608123633010201015c0200",
    "101736595fbfc8d361f990557c35c1301c42787e061008050c016b01064d0200",
    "0106007838365f36342f4c696e757820322e342e7878006903010a0066034003",
    "00021fe80102010200062201010001020000000702c10208010603284b3a0001",
    "02000000000000040101011b010102057b00000102010e030000000000000000",
    "0000000030001010000000002057b0101010300194f52412d30313430333a2",
    "08010602000000000000000001010101013100000000010707787e0608123633",
    "0903010005024be91d",                       # STA + EOR
    "040101022bcd010102057b000001",             # OER region
    "0701c102",                                  # RXD + a number
    "0e0100020000000000",                        # LOB op
    "1d",                                        # end-of-response alone
    "0c0100",                                    # short / marker-ish
    "21010108",                                  # TOKEN(33) marker
]

# decode_packet seeds the row decoder with (Cursor, RowFormat, Rows).
_ACC = (None, None, [])

# Per-input hang guard (Unix). decode_packet must return or raise quickly; if it
# spins, SIGALRM interrupts it and the input is reported as a hang to fix.
_HAS_ALARM = hasattr(signal, "SIGALRM")


class _Timeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _Timeout()


def _mutate(data: bytes, rng: random.Random) -> bytes:
    b = bytearray(data)
    op = rng.randrange(5)
    if op == 0 and b:                       # flip a few bits
        for _ in range(rng.randint(1, 5)):
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
    elif op == 1:                           # truncate
        b = b[:rng.randrange(len(b) + 1)]
    elif op == 2:                           # append random bytes
        b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 24)))
    elif op == 3 and len(b) > 1:            # overwrite a run (often a length)
        i = rng.randrange(len(b))
        for j in range(i, min(i + rng.randint(1, 4), len(b))):
            b[j] = rng.randrange(256)
    else:                                   # splice two seeds
        b = bytearray(data) + bytearray(
            bytes.fromhex(rng.choice(_SEEDS)))
    return bytes(b)


class TestDecoderFuzz(unittest.TestCase):
    def test_decode_packet_never_hangs_or_reads_oob(self):
        rng = random.Random(0xC0FFEE)
        if _HAS_ALARM:
            old = signal.signal(signal.SIGALRM, _on_alarm)
        try:
            for _ in range(4000):
                data = _mutate(bytes.fromhex(rng.choice(_SEEDS)), rng)
                if _HAS_ALARM:
                    signal.setitimer(signal.ITIMER_REAL, 2.0)
                try:
                    decode_packet(data, _ACC)
                except _Timeout:
                    self.fail("decode_packet hung on input: " + data.hex())
                except Exception:
                    # Any clean exception is acceptable — the connection layer
                    # treats a decode failure as a protocol error. We only fail
                    # on a hang (above) or a hard interpreter crash (which would
                    # take the process down, not raise).
                    pass
                finally:
                    if _HAS_ALARM:
                        signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            if _HAS_ALARM:
                signal.signal(signal.SIGALRM, old)

    def test_decoders_handle_empty_and_single_byte(self):
        # Degenerate inputs every dispatcher must survive.
        for i in range(256):
            try:
                decode_packet(bytes([i]), _ACC)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
