# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline guard for the benchmark harness (#166): it imports and its pure
formatting helper works. The benchmark itself needs a live Oracle and is run
manually (see tools/benchmark.py)."""

import importlib.util
import io
import os
import unittest
from contextlib import redirect_stdout

_PATH = os.path.join(os.path.dirname(__file__), "..", "tools", "benchmark.py")


def _load():
    spec = importlib.util.spec_from_file_location("pyoracle_benchmark", _PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestBenchmarkHarness(unittest.TestCase):
    def test_imports(self):
        mod = _load()
        for fn in ("bench_connect", "bench_insert", "bench_executemany",
                   "bench_fetch", "bench_fetch_df", "main"):
            self.assertTrue(callable(getattr(mod, fn)))

    def test_report_formats_a_rate(self):
        mod = _load()
        buf = io.StringIO()
        with redirect_stdout(buf):
            mod._report("scenario", 1000, 0.5)
        out = buf.getvalue()
        self.assertIn("scenario", out)
        self.assertIn("1000", out)
        self.assertIn("2,000", out)            # 1000 rows / 0.5 s
        self.assertIn("rows/s", out)

    def test_report_zero_time_is_safe(self):
        mod = _load()
        with redirect_stdout(io.StringIO()):
            mod._report("instant", 5, 0.0)     # no ZeroDivisionError


if __name__ == "__main__":
    unittest.main()
