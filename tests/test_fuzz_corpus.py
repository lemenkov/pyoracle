# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Replay the vendored SeerODBC response-decoder fuzz corpus through pyoracle's
per-codec decoders (#165 follow-up).

The sibling SeerODBC project fuzzes the shared TNS codecs and feeds each corpus
blob to *every* decoder; we mirror that here, replaying ~1600 coverage-guided
inputs through pyoracle's scalar decoders plus decode_oson and decode_dalc. The
contract is the loose, memory-safety one: a malformed/hostile blob may decode or
raise any clean exception, but must never hang the client (a decode that spins
is exactly the decode_oson DoS the count/cycle bounds fixed). A per-call SIGALRM
turns a spin into a test failure; any raised exception is acceptable.

Corpus data + provenance: tests/fuzz_corpus_decoders.txt. The VECTOR image
corpus is intentionally not replayed here -- decode_vector has its own unbounded
input to bound first, tracked separately."""

import os
import signal
import unittest

from oracle.oson import decode_oson
from oracle.tns import decode_dalc
from oracle.types import (
    decode_binary_double, decode_binary_float, decode_date, decode_interval_ds,
    decode_interval_ym, decode_number,
)

_CORPUS = os.path.join(os.path.dirname(__file__), "fuzz_corpus_decoders.txt")

# Every decoder of server-controlled column/field bytes that a corpus blob could
# reach (SeerODBC feeds each blob to all of them; there is no selector byte).
_BATTERY = (
    decode_number, decode_date, decode_binary_float, decode_binary_double,
    decode_interval_ym, decode_interval_ds, decode_oson, decode_dalc,
)

# decode_oson's bounds make every corpus blob return/raise in well under a
# millisecond; the cap only fires on a genuine regression to unbounded work.
_CALL_CAP_SECONDS = 5.0
_HAS_ALARM = hasattr(signal, "SIGALRM")


class _Timeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _Timeout()


def _load_corpus():
    blobs = []
    with open(_CORPUS, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                blobs.append(bytes.fromhex(line))
    return blobs


class TestFuzzCorpusReplay(unittest.TestCase):

    def test_battery_never_hangs(self):
        blobs = _load_corpus()
        # Guard against a corpus file that failed to vendor / load.
        self.assertGreater(len(blobs), 1000)
        if _HAS_ALARM:
            previous = signal.signal(signal.SIGALRM, _on_alarm)
        try:
            for blob in blobs:
                for decode in _BATTERY:
                    if _HAS_ALARM:
                        signal.setitimer(signal.ITIMER_REAL, _CALL_CAP_SECONDS)
                    try:
                        decode(blob)
                    except _Timeout:
                        self.fail(
                            f"{decode.__name__} hung on corpus blob: {blob.hex()}")
                    except Exception:  # noqa: BLE001
                        # Loose contract: any clean exception is acceptable -- the
                        # connection layer treats a decode failure as a protocol
                        # error. Only a hang (above) or hard crash is a failure.
                        pass
                    finally:
                        if _HAS_ALARM:
                            signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            if _HAS_ALARM:
                signal.signal(signal.SIGALRM, previous)


if __name__ == "__main__":
    unittest.main()
