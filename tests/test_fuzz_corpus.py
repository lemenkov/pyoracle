# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Replay the vendored SeerODBC fuzz corpora through pyoracle's decoders (#165).

The sibling SeerODBC project fuzzes the shared TNS codecs and image decoders,
feeding each corpus blob to *every* decoder. We mirror that here:

  * the response-decoder corpus (~1600 blobs) is replayed through the scalar
    decoders plus decode_oson and decode_dalc; and
  * the VECTOR/ADT image corpus (~1100 blobs) through decode_vector.

The contract is twofold. Memory-safety (#165): a malformed/hostile blob must
never hang the client -- a decode that spins is the decode_oson / decode_vector
DoS the count/cycle bounds fixed, and a per-call SIGALRM turns a spin into a
failure. Exception hygiene (#230): a malformed blob may decode or raise a
*domain* exception (a DatabaseError subclass, or the codec's own OsonError /
VectorError), but never a raw ValueError / IndexError / UnicodeDecodeError /
decimal.InvalidOperation leaking the implementation.

Corpus data + provenance: tests/fuzz_corpus_decoders.txt,
tests/fuzz_corpus_images.txt."""

import os
import signal
import unittest

from oracle.exceptions import DatabaseError
from oracle.oson import OsonError, decode_oson
from oracle.tns import decode_dalc
from oracle.types import (
    decode_binary_double,
    decode_binary_float,
    decode_date,
    decode_interval_ds,
    decode_interval_ym,
    decode_number,
)
from oracle.vector import VectorError, decode_vector

_HERE = os.path.dirname(__file__)
_DECODERS_CORPUS = os.path.join(_HERE, 'fuzz_corpus_decoders.txt')
_IMAGES_CORPUS = os.path.join(_HERE, 'fuzz_corpus_images.txt')

# Every decoder of server-controlled column/field bytes a response-corpus blob
# could reach (SeerODBC feeds each blob to all of them; there is no selector
# byte).
_DECODER_BATTERY = (
    decode_number,
    decode_date,
    decode_binary_float,
    decode_binary_double,
    decode_interval_ym,
    decode_interval_ds,
    decode_oson,
    decode_dalc,
)
# The image corpus targets the ADT/VECTOR image decoders; decode_vector is the
# self-describing one pyoracle exposes (object/collection images need a type
# descriptor, so they are not reachable from raw bytes alone).
_IMAGE_BATTERY = (decode_vector,)

# The exception types a decoder may raise on malformed input (#230): the DB-API
# hierarchy plus the two codec-specific errors. Anything else is a raw leak.
_DOMAIN_ERRORS = (DatabaseError, OsonError, VectorError)

# The count/cycle bounds make every corpus blob return/raise in well under a
# millisecond; the cap only fires on a genuine regression to unbounded work.
_CALL_CAP_SECONDS = 5.0
_HAS_ALARM = hasattr(signal, 'SIGALRM')


class _Timeout(Exception):
    pass


def _on_alarm(signum, frame):
    raise _Timeout()


def _load_corpus(path):
    blobs = []
    with open(path, encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith('#'):
                blobs.append(bytes.fromhex(line))
    return blobs


def _assert_bounded_and_typed(test, blobs, battery):
    if _HAS_ALARM:
        previous = signal.signal(signal.SIGALRM, _on_alarm)
    try:
        for blob in blobs:
            for decode in battery:
                if _HAS_ALARM:
                    signal.setitimer(signal.ITIMER_REAL, _CALL_CAP_SECONDS)
                try:
                    decode(blob)
                except _Timeout:
                    test.fail(f'{decode.__name__} hung on corpus blob: {blob.hex()}')
                except _DOMAIN_ERRORS:
                    pass  # a clean, catchable decode error
                except Exception as exc:  # noqa: BLE001
                    test.fail(
                        f'{decode.__name__} raised non-domain '
                        f'{type(exc).__name__} on corpus blob: {blob.hex()}'
                    )
                finally:
                    if _HAS_ALARM:
                        signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        if _HAS_ALARM:
            signal.signal(signal.SIGALRM, previous)


class TestFuzzCorpusReplay(unittest.TestCase):
    def test_decoder_battery_bounded_and_typed(self):
        blobs = _load_corpus(_DECODERS_CORPUS)
        # Guard against a corpus file that failed to vendor / load.
        self.assertGreater(len(blobs), 1000)
        _assert_bounded_and_typed(self, blobs, _DECODER_BATTERY)

    def test_vector_image_corpus_bounded_and_typed(self):
        blobs = _load_corpus(_IMAGES_CORPUS)
        self.assertGreater(len(blobs), 1000)
        _assert_bounded_and_typed(self, blobs, _IMAGE_BATTERY)


if __name__ == '__main__':
    unittest.main()
