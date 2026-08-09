#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Extended ad-hoc decoder fuzzer (#165).

Mutation-fuzzes seerdb.tns.decode_packet from the same seed corpus the bounded
CI test (tests/test_fuzz.py) uses, but for as many iterations as you ask — for
hunting a latent hang / out-of-bounds read the short CI run would not reach.

    python3 tools/fuzz_decoder.py [iterations] [rng_seed]

Reports any input that hangs (caught via SIGALRM) or raises an unexpected
crash class; ordinary decode failures are expected and ignored. Exit code 1 if
anything was found.
"""

import random
import signal
import sys

sys.path.insert(0, ".")
from tests.test_fuzz import _SEEDS, _ACC, _mutate          # noqa: E402
from seerdb.tns import decode_packet                       # noqa: E402


class _Timeout(Exception):
    pass


def main() -> int:
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 500_000
    rng = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(_Timeout()))
    findings = 0
    for n in range(iterations):
        data = _mutate(bytes.fromhex(rng.choice(_SEEDS)), rng)
        signal.setitimer(signal.ITIMER_REAL, 3.0)
        try:
            decode_packet(data, _ACC)
        except _Timeout:
            print(f"HANG on: {data.hex()}")
            findings += 1
        except RecursionError:
            print(f"RECURSION on: {data.hex()}")
            findings += 1
        except (MemoryError, SystemError) as exc:
            print(f"{type(exc).__name__} on: {data.hex()}")
            findings += 1
        except Exception:
            pass                                            # expected
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        if n and n % 100_000 == 0:
            print(f"  ...{n} iterations, {findings} findings", file=sys.stderr)
    print(f"done: {iterations} iterations, {findings} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
