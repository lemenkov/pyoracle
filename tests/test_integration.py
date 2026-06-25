# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# Integration tests that talk to a real Oracle database. Disabled unless the
# connection parameters are exported in the environment:
#
#   PYORACLE_TEST_USER       (required — gate; if unset, all tests skip)
#   PYORACLE_TEST_PASSWORD   (required)
#   PYORACLE_TEST_HOST       (default 'localhost')
#   PYORACLE_TEST_PORT       (default 1521)
#   PYORACLE_TEST_SERVICE    (default 'XE')
#
# The DB user only needs CREATE SESSION and CREATE TABLE privileges plus a
# writable tablespace. Each test creates and drops its own scratch table.

import datetime
import math
import os
import ssl
import unittest
from decimal import Decimal

import oracle
from oracle.tns_consts import FIELD_VERSION_12_1, FIELD_VERSION_10_2

# Features the Oracle 9i (fv2) server genuinely lacks, keyed by a substring of
# the test method name. A 9i (field_version < 10.2) connection skips these with
# a clear reason — the same bar 10g uses for 12c+/23ai features (#171). These
# are *server* limitations or capabilities pyoracle deliberately does not offer
# on fv2, not fixable fv2 bind gaps (those are #172 dates, #173 intervals,
# #174 national charset).
_FV2_UNSUPPORTED = (
    ("binary_double", "BINARY_DOUBLE is a 10g+ type; Oracle 9i lacks it"),
    ("binary_float", "BINARY_FLOAT is a 10g+ type; Oracle 9i lacks it"),
    ("kib", "Oracle 9i has no streamed LOB/LONG bind path (#169)"),
    ("clob_bind_above_varchar2_cap",
     "Oracle 9i has no streamed LOB/LONG bind path (#169)"),
    ("clob_bind_spans_multiple_packets",
     "Oracle 9i has no streamed LOB/LONG bind path (#169)"),
    ("blob_bind_round_trip_all_byte_values",
     "Oracle 9i has no streamed LOB/LONG bind path (#169)"),
    ("error_then_large_lob",
     "Oracle 9i has no streamed LOB/LONG bind path (#169)"),
    # Behavioural features the fv2 path does not implement (#168): they now
    # raise a clean NotSupportedError or exercise a capability 9i lacks, rather
    # than silently misbehaving, so the tests skip on 9i.
    ("executemany", "array DML (executemany) is not supported on Oracle 9i"),
    ("batcherror", "array DML batcherrors are not supported on Oracle 9i"),
    ("refcursor", "REF CURSOR is not supported on Oracle 9i (fv2)"),
    ("ref_bind", "REF / object types are not supported on Oracle 9i"),
    ("changepassword", "changepassword is not supported on Oracle 9i"),
    ("cache_evicts", "the cursor cache is a fv4+ feature; 9i re-parses"),
    ("reuses_cursor", "the cursor cache is a fv4+ feature; 9i re-parses"),
    ("pipeline", "the pipeline test uses array DML, unsupported on Oracle 9i"),
    # The 9i test DB is WE8ISO8859P1 (Latin-1). #174 made representable VARCHAR2
    # text round-trip (see test_db_charset_varchar_roundtrip) and full Unicode
    # work through DB_TYPE_NVARCHAR / DB_TYPE_NCHAR (test_national_char_var_bind,
    # which runs on every tier). What remains genuinely unsupported on 9i is a
    # *plain str* bind of non-Latin-1 / supplementary text: it routes through the
    # DB charset, which cannot hold those characters. Those tests stay skipped.
    ("varchar_utf8", "plain str non-Latin-1 can't store in 9i WE8ISO8859P1 (#174)"),
    ("varchar_supplementary",
     "plain str supplementary char can't store in 9i WE8ISO8859P1 (#174)"),
    ("nvarchar", "plain str -> NVARCHAR2 via 9i DB charset; use DB_TYPE_NVARCHAR (#174)"),
    ("nchar", "plain str -> NCHAR via 9i DB charset; use DB_TYPE_NCHAR (#174)"),
    ("nclob", "9i national-charset LOB handling deferred (#174)"),
)


def _fv2_skip_reason(test_method_name: str) -> str | None:
    # The skip reason for a test whose feature Oracle 9i (fv2) lacks, or None.
    for Pattern, Reason in _FV2_UNSUPPORTED:
        if Pattern in test_method_name:
            return Reason
    return None

# Resolve the TLS proxy fixture without depending on the `tests` package
# layout (works under both `python -m unittest tests.test_integration` and
# discovery from the repo root).
import sys as _sys
_sys.path.insert(0, os.path.dirname(__file__))
from _tls_proxy import CERT_PATH, TLSProxy  # noqa: E402
from _redirect_listener import RedirectListener  # noqa: E402


_USER = os.environ.get('PYORACLE_TEST_USER')
_PASSWORD = os.environ.get('PYORACLE_TEST_PASSWORD', '')
_HOST = os.environ.get('PYORACLE_TEST_HOST', 'localhost')
_PORT = int(os.environ.get('PYORACLE_TEST_PORT', '1521'))
_SERVICE = os.environ.get('PYORACLE_TEST_SERVICE', 'XE')
# Advertise a 12c+ TTC field version (e.g. 16 = 21.1) to run the suite against
# a 12c+ server; unset/0 keeps the 11g default. Lets the same suite cover both
# testbeds (issue #27).
_FIELD_VERSION = int(os.environ.get('PYORACLE_TEST_FIELD_VERSION', '0'))
_FV_KW = {'field_version': _FIELD_VERSION} if _FIELD_VERSION else {}

_SKIP_REASON = (
    "integration tests require a real DB connection; "
    "set PYORACLE_TEST_USER (and PYORACLE_TEST_PASSWORD) to enable"
)


# Pause before each connection. Oracle XE's listener throttles rapid logins
# ("logon storm" protection) and cancels early statements on the throttled
# session with ORA-01013. The whole suite opens ~150 connections; on a busy or
# freshly-booted XE (e.g. CI) the default 0.05 s isn't always enough, so the
# delay is tunable via PYORACLE_TEST_CONNECT_DELAY (CI sets it higher).
_CONNECT_DELAY = float(os.environ.get('PYORACLE_TEST_CONNECT_DELAY', '0.05'))


def _connect():
    import time
    time.sleep(_CONNECT_DELAY)
    return oracle.connect(
        host=_HOST, port=_PORT,
        user=_USER, password=_PASSWORD,
        service_name=_SERVICE,
        autocommit=True,
        **_FV_KW,
    )


# Number of times to replay a whole test that tripped ORA-01013, and the pause
# between attempts. See `_IntegrationBase.run`.
_THROTTLE_RETRIES = int(os.environ.get('PYORACLE_TEST_THROTTLE_RETRIES', '2'))
_THROTTLE_RETRY_DELAY = float(os.environ.get('PYORACLE_TEST_THROTTLE_DELAY', '0.5'))


class _CaptureResult(unittest.TestResult):
    """Runs one test attempt and remembers its single outcome (with the
    original exc_info) instead of reporting it. Lets `_IntegrationBase.run`
    decide whether the attempt was a transient ORA-01013 throttle cancel worth
    retrying, then forward the final outcome to the real result — without
    double-running the test or losing the traceback."""

    def __init__(self):
        super().__init__()
        self.outcome = ('success', None)

    def addSuccess(self, test):
        self.outcome = ('success', None)

    def addError(self, test, err):
        self.outcome = ('error', err)        # err = exc_info tuple

    def addFailure(self, test, err):
        self.outcome = ('failure', err)

    def addSkip(self, test, reason):
        self.outcome = ('skip', reason)

    def is_throttle(self) -> bool:
        kind, payload = self.outcome
        if kind not in ('error', 'failure') or not payload:
            return False
        exc = payload[1]
        return isinstance(exc, oracle.OperationalError) \
            and getattr(exc, 'code', None) == 1013


class _IntegrationBase(unittest.TestCase):
    """Per-test connection; fresh cursor + scratch table per test.

    Oracle XE's listener throttles rapid logins ("logon storm"
    protection) and cancels statements on a throttled session with
    ORA-01013 ("user requested cancel of current operation"). This is
    documented server behaviour, not a driver bug — production code uses
    connection pools (`oracle.Pool`, issue #6) and doesn't hit it. The
    suite defends in three layers: `_connect` paces logins
    (PYORACLE_TEST_CONNECT_DELAY), `setUp` retries the connect / initial
    drop, and `run` (below) replays a whole test that still tripped
    ORA-01013 mid-body — each replay gets a fresh connection via setUp, so
    it is safe and keeps CI from flaking on the throttle.
    """
    TABLE = "PYORACLE_TEST"

    def __init_subclass__(cls, **kwargs):
        # Give each integration class its OWN table name (#170). All classes
        # used to share "PYORACLE_TEST", so a single stuck lock — e.g. a 9i
        # connection killed mid-DML leaving a zombie session (#168/#169) — would
        # block every later class's setUp/tearDown DROP and cascade into dozens
        # of phantom ORA-00054, especially on the slow 9i VM. A unique name per
        # class contains the blast radius to that one class. A subclass that
        # sets its own TABLE keeps it.
        super().__init_subclass__(**kwargs)
        if 'TABLE' not in cls.__dict__:
            Name = cls.__name__.replace('Integration', '') or cls.__name__
            cls.TABLE = ('PYO_' + Name.upper())[:30]

    def run(self, result=None):
        import time
        for attempt in range(_THROTTLE_RETRIES + 1):
            capture = _CaptureResult()
            super().run(capture)
            if attempt == _THROTTLE_RETRIES or not capture.is_throttle():
                break
            time.sleep(_THROTTLE_RETRY_DELAY)
        # Forward the final attempt's outcome to the real result so reporting
        # (counts, tracebacks, verbose output) is unaffected by the retry.
        if result is not None:
            kind, payload = capture.outcome
            result.startTest(self)
            try:
                if kind == 'error':
                    result.addError(self, payload)
                elif kind == 'failure':
                    result.addFailure(self, payload)
                elif kind == 'skip':
                    result.addSkip(self, payload)
                else:
                    result.addSuccess(self)
            finally:
                result.stopTest(self)
        return result

    def setUp(self):
        Last: Exception = RuntimeError("setUp: connection retries exhausted")
        for _ in range(5):
            try:
                self.conn = _connect()
                self.cur = self.conn.cursor()
                self._skip_if_fv2_unsupported()
                self._drop_silently(self.cur)
                return
            except oracle.OperationalError as e:
                if e.code != 1013:
                    raise
                Last = e
                # Bleed a few ms and try a fresh connection.
                try:
                    self.conn.close()
                except Exception:
                    # Best-effort: we are retrying with a fresh connection;
                    # a failed close on the stale one does not matter.
                    pass
                import time
                time.sleep(0.05)
        raise Last

    def _skip_if_fv2_unsupported(self):
        # On a 9i (fv2) connection, skip the tests whose feature the 9i server
        # genuinely lacks — same bar 10g uses for 12c+/23ai features (#171).
        # Close the connection first: a SkipTest from setUp means tearDown does
        # not run, so we must not leak the connection (a leak on the slow 9i VM
        # piles up sessions).
        if self.conn.field_version >= FIELD_VERSION_10_2:
            return
        Reason = _fv2_skip_reason(self._testMethodName)
        if Reason is not None:
            self.conn.close()
            self.skipTest(Reason)

    def tearDown(self):
        # The test may have closed self.cur — always reach for a fresh one.
        try:
            cleanup = self.conn.cursor()
            try:
                self._drop_silently(cleanup)
            except oracle.OperationalError as e:
                # The setUp/tearDown cleanup is best-effort; ORA-01013
                # here just means "Oracle cancelled the cleanup
                # statement", and the next test's setUp will retry.
                if e.code != 1013:
                    raise
            finally:
                cleanup.close()
        finally:
            self.conn.close()

    def _drop_silently(self, cur):
        try:
            cur.execute(f"DROP TABLE {self.TABLE}")
        except oracle.DatabaseError as e:
            # ORA-00942: table or view does not exist — expected on first run.
            if e.code != 942:
                raise


@unittest.skipUnless(_USER, _SKIP_REASON)
class TypesIntegration(_IntegrationBase):
    """Verify that wire bytes are coerced into the right Python types."""

    def _round_trip(self, ddl_col: str, insert_value: str):
        """CREATE + INSERT + SELECT one column, return the fetched cell."""
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v {ddl_col})")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ({insert_value})")
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 1)
        return rows[0][0]

    # ----- NUMBER -----

    def test_number_positive_int(self):
        v = self._round_trip("NUMBER", "42")
        self.assertEqual(v, 42)
        self.assertIsInstance(v, int)

    def test_number_zero(self):
        v = self._round_trip("NUMBER", "0")
        self.assertEqual(v, 0)
        self.assertIsInstance(v, int)

    def test_number_negative_int(self):
        v = self._round_trip("NUMBER", "-17")
        self.assertEqual(v, -17)
        self.assertIsInstance(v, int)

    def test_number_big_int(self):
        v = self._round_trip("NUMBER", "1234567890123456")
        self.assertEqual(v, 1234567890123456)
        self.assertIsInstance(v, int)

    def test_number_decimal_positive(self):
        v = self._round_trip("NUMBER(12,4)", "3.1415")
        self.assertEqual(v, Decimal("3.1415"))
        self.assertIsInstance(v, Decimal)

    def test_number_decimal_negative(self):
        v = self._round_trip("NUMBER", "-0.5")
        self.assertEqual(v, Decimal("-0.5"))
        self.assertIsInstance(v, Decimal)

    def test_number_small_fractional(self):
        v = self._round_trip("NUMBER(12,4)", "0.0001")
        self.assertEqual(v, Decimal("0.0001"))

    # ----- VARCHAR / CHAR -----

    def test_varchar_ascii(self):
        v = self._round_trip("VARCHAR2(40)", "'hello world'")
        self.assertEqual(v, "hello world")
        self.assertIsInstance(v, str)

    def test_varchar_utf8(self):
        v = self._round_trip("VARCHAR2(40)", "'utf-8 ✓ 中文'")
        self.assertEqual(v, "utf-8 ✓ 中文")

    def test_varchar_supplementary_plane(self):
        # Characters above the BMP (emoji, U+1F600 etc.) are 4-byte UTF-8 /
        # surrogate pairs in UTF-16. They round-trip only when the client
        # advertises AL32UTF8 (real UTF-8); Oracle's legacy "UTF8" (CESU-8)
        # 6-byte-encodes them and decode then yields replacement chars (#29).
        v = self._round_trip("VARCHAR2(40)", "'hi 😀🎉 端 end'")
        self.assertEqual(v, "hi 😀🎉 端 end")

    def test_char_preserves_padding(self):
        v = self._round_trip("CHAR(10)", "'x'")
        self.assertEqual(v, "x" + " " * 9)
        self.assertEqual(len(v), 10)

    # ----- NCHAR / NVARCHAR (national character set) -----

    def test_nvarchar_non_ascii(self):
        v = self._round_trip("NVARCHAR2(40)", "N'national ünî 中'")
        self.assertEqual(v, "national ünî 中")
        self.assertIsInstance(v, str)

    def test_nvarchar_supplementary_plane(self):
        v = self._round_trip("NVARCHAR2(40)", "N'n 😀🎉 end'")
        self.assertEqual(v, "n 😀🎉 end")

    def test_nchar_preserves_padding(self):
        v = self._round_trip("NCHAR(6)", "N'hï'")
        self.assertEqual(v, "hï" + " " * 4)
        self.assertEqual(len(v), 6)

    # ----- DATE / TIMESTAMP -----

    def test_date(self):
        v = self._round_trip("DATE", "DATE '2026-05-23'")
        self.assertEqual(v, datetime.datetime(2026, 5, 23, 0, 0, 0))
        self.assertIsInstance(v, datetime.datetime)

    def test_date_min(self):
        v = self._round_trip("DATE", "DATE '0001-01-01'")
        self.assertEqual(v, datetime.datetime(1, 1, 1))

    def test_timestamp_microseconds(self):
        v = self._round_trip(
            "TIMESTAMP", "TIMESTAMP '2026-05-23 10:11:12.345678'"
        )
        self.assertEqual(v, datetime.datetime(2026, 5, 23, 10, 11, 12, 345678))

    def test_timestamp_max(self):
        v = self._round_trip(
            "TIMESTAMP", "TIMESTAMP '9999-12-31 23:59:59.999999'"
        )
        self.assertEqual(v, datetime.datetime(9999, 12, 31, 23, 59, 59, 999999))

    def test_timestamp_with_negative_tz(self):
        v = self._round_trip(
            "TIMESTAMP WITH TIME ZONE",
            "TIMESTAMP '2026-05-23 10:11:12.345678 -05:30'",
        )
        # Oracle normalises to UTC and tags the offset; both pieces must match.
        self.assertIsNotNone(v.tzinfo)
        self.assertEqual(v.utcoffset(), datetime.timedelta(hours=-5, minutes=-30))
        expected = datetime.datetime(
            2026, 5, 23, 10, 11, 12, 345678,
            tzinfo=datetime.timezone(datetime.timedelta(hours=-5, minutes=-30)),
        )
        self.assertEqual(v, expected)

    def test_timestamp_with_positive_tz(self):
        v = self._round_trip(
            "TIMESTAMP WITH TIME ZONE",
            "TIMESTAMP '2026-05-23 10:11:12 +14:00'",
        )
        self.assertEqual(v.utcoffset(), datetime.timedelta(hours=14))

    def test_timestamp_with_named_region_winter(self):
        # Named region (issue #20): offset resolved via zoneinfo, so January is
        # standard time (EST, -05:00).
        v = self._round_trip(
            "TIMESTAMP WITH TIME ZONE",
            "FROM_TZ(TIMESTAMP '2024-01-15 12:00:00', 'US/Eastern')",
        )
        self.assertEqual(v.utcoffset(), datetime.timedelta(hours=-5))
        self.assertEqual(v.replace(tzinfo=None),
                         datetime.datetime(2024, 1, 15, 12, 0, 0))

    def test_timestamp_with_named_region_dst(self):
        # Same region in July is daylight time (EDT, -04:00) — proof the offset
        # comes from the live IANA database, not a fixed per-region value.
        v = self._round_trip(
            "TIMESTAMP WITH TIME ZONE",
            "FROM_TZ(TIMESTAMP '2024-07-15 12:00:00', 'US/Eastern')",
        )
        self.assertEqual(v.utcoffset(), datetime.timedelta(hours=-4))

    # ----- BINARY_FLOAT / BINARY_DOUBLE -----

    def test_binary_float(self):
        v = self._round_trip("BINARY_FLOAT", "1.5f")
        self.assertEqual(v, 1.5)
        self.assertIsInstance(v, float)

    def test_binary_float_negative(self):
        self.assertEqual(self._round_trip("BINARY_FLOAT", "-2.25f"), -2.25)

    def test_binary_double(self):
        v = self._round_trip("BINARY_DOUBLE", "1234.5678d")
        self.assertEqual(v, 1234.5678)
        self.assertIsInstance(v, float)

    def test_binary_double_infinity(self):
        self.assertEqual(self._round_trip("BINARY_DOUBLE", "binary_double_infinity"),
                         math.inf)

    def test_binary_double_nan(self):
        self.assertTrue(math.isnan(
            self._round_trip("BINARY_DOUBLE", "binary_double_nan")))

    # ----- INTERVAL -----

    def test_interval_ds(self):
        v = self._round_trip("INTERVAL DAY(4) TO SECOND(6)",
                             "INTERVAL '5 04:03:02.123456' DAY TO SECOND")
        self.assertEqual(v, datetime.timedelta(days=5, hours=4, minutes=3,
                                               seconds=2, microseconds=123456))
        self.assertIsInstance(v, datetime.timedelta)

    def test_interval_ds_negative(self):
        v = self._round_trip("INTERVAL DAY(4) TO SECOND(6)",
                             "INTERVAL '-0 00:00:01.5' DAY TO SECOND")
        self.assertEqual(v, datetime.timedelta(seconds=-1.5))

    def test_interval_ym(self):
        v = self._round_trip("INTERVAL YEAR(4) TO MONTH",
                             "INTERVAL '3-7' YEAR TO MONTH")
        self.assertEqual(v, oracle.IntervalYM(3, 7))
        self.assertIsInstance(v, oracle.IntervalYM)

    def test_interval_ym_negative(self):
        v = self._round_trip("INTERVAL YEAR(4) TO MONTH",
                             "INTERVAL '-1-2' YEAR TO MONTH")
        self.assertEqual(v, oracle.IntervalYM(-1, -2))

    # ----- ROWID -----

    def test_rowid_matches_rowidtochar(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        for i in range(3):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ({i})")
        self.cur.execute(
            f"SELECT ROWID, ROWIDTOCHAR(ROWID) FROM {self.TABLE} ORDER BY id")
        for driver_rowid, ref in self.cur.fetchall():
            self.assertIsInstance(driver_rowid, str)
            self.assertEqual(driver_rowid, ref)

    def test_rowid_usable_as_bind(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (42)")
        self.cur.execute(f"SELECT ROWID FROM {self.TABLE}")
        rid = self.cur.fetchone()[0]
        self.cur.execute(f"SELECT id FROM {self.TABLE} WHERE ROWID = :r", [rid])
        self.assertEqual(self.cur.fetchone(), (42,))

    def test_urowid_index_organized_table(self):
        # An index-organized table's ROWID is a UROWID (type 208): a
        # "*"-prefixed base64 string, and usable as a bind.
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} "
            f"(id NUMBER PRIMARY KEY, v VARCHAR2(20)) ORGANIZATION INDEX")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'a')")
        self.cur.execute(f"SELECT ROWID, id FROM {self.TABLE}")
        rid, idv = self.cur.fetchone()
        self.assertIsInstance(rid, str)
        self.assertTrue(rid.startswith("*"))
        self.assertEqual(idv, 1)
        self.cur.execute(f"SELECT id FROM {self.TABLE} WHERE ROWID = :r", [rid])
        self.assertEqual(self.cur.fetchone(), (1,))

    # ----- LONG / LONG RAW -----

    def test_long(self):
        v = self._round_trip("LONG", "'a long value'")
        self.assertEqual(v, "a long value")
        self.assertIsInstance(v, str)

    def test_long_multichunk(self):
        # > 1 wire chunk, exercising the chunk loop.
        v = self._round_trip("LONG", "RPAD('X', 700, 'X')")
        self.assertEqual(v, "X" * 700)

    def test_long_null(self):
        self.assertIsNone(self._round_trip("LONG", "NULL"))

    def test_long_raw(self):
        v = self._round_trip("LONG RAW", "HEXTORAW('DEADBEEFCAFE')")
        self.assertEqual(v, bytes.fromhex("DEADBEEFCAFE"))
        self.assertIsInstance(v, bytes)

    def test_long_raw_null(self):
        self.assertIsNone(self._round_trip("LONG RAW", "NULL"))

    def test_long_not_last_column(self):
        # A LONG followed by another column: the reader must leave the stream
        # aligned for the trailing NUMBER.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (txt LONG, id NUMBER)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('hi', 5)")
        self.cur.execute(f"SELECT txt, id FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), ("hi", 5))

    # ----- NULL -----

    def test_null_number(self):
        v = self._round_trip("NUMBER", "NULL")
        self.assertIsNone(v)

    def test_null_varchar(self):
        v = self._round_trip("VARCHAR2(40)", "NULL")
        self.assertIsNone(v)

    def test_null_date(self):
        v = self._round_trip("DATE", "NULL")
        self.assertIsNone(v)


@unittest.skipUnless(_USER, _SKIP_REASON)
class CursorIntegration(_IntegrationBase):
    """Verify the PEP 249 Cursor surface."""

    def _setup_rows(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} "
            f"(id NUMBER, name VARCHAR2(40), score NUMBER(6,2))"
        )
        for row in [
            (1, 'alpha',   Decimal("3.14")),
            (2, 'beta',    Decimal("9.99")),
            (3, 'gamma',   Decimal("100.50")),
            (4, 'delta',   Decimal("-1.25")),
            (5, None,      None),
        ]:
            name = "NULL" if row[1] is None else f"'{row[1]}'"
            score = "NULL" if row[2] is None else str(row[2])
            self.cur.execute(
                f"INSERT INTO {self.TABLE} VALUES ({row[0]}, {name}, {score})"
            )

    # ----- description -----

    def test_description_is_7_tuples(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id, name, score FROM {self.TABLE}")
        self.assertIsNotNone(self.cur.description)
        for col in self.cur.description:
            self.assertEqual(len(col), 7)

    def test_description_names_are_str(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id, name FROM {self.TABLE}")
        names = [c[0] for c in self.cur.description]
        self.assertEqual(names, ["ID", "NAME"])
        for n in names:
            self.assertIsInstance(n, str)

    def test_description_precision_scale(self):
        self._setup_rows()
        self.cur.execute(f"SELECT score FROM {self.TABLE}")
        # score is NUMBER(6,2): precision=6, scale=2.
        (_, _, _, _, precision, scale, _) = self.cur.description[0]
        self.assertEqual(precision, 6)
        self.assertEqual(scale, 2)

    def test_description_none_after_ddl(self):
        # DDL doesn't produce a result set.
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER)"
        )
        self.assertIsNone(self.cur.description)

    # ----- rowcount -----

    def test_rowcount_select_matches(self):
        self._setup_rows()
        self.cur.execute(f"SELECT * FROM {self.TABLE}")
        self.assertEqual(self.cur.rowcount, 5)

    def test_rowcount_empty_select(self):
        self._setup_rows()
        self.cur.execute(f"SELECT * FROM {self.TABLE} WHERE id > 1000")
        self.assertEqual(self.cur.rowcount, 0)

    # ----- fetch* -----

    def test_fetchone_returns_rows_then_none(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        self.assertEqual(self.cur.fetchone(), (1,))
        self.assertEqual(self.cur.fetchone(), (2,))
        # Drain.
        for _ in range(3):
            self.cur.fetchone()
        self.assertIsNone(self.cur.fetchone())

    def test_fetchmany_with_size(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        batch = self.cur.fetchmany(3)
        self.assertEqual(batch, [(1,), (2,), (3,)])

    def test_fetchmany_default_arraysize(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        self.cur.arraysize = 2
        self.assertEqual(self.cur.fetchmany(), [(1,), (2,)])

    def test_fetchmany_more_than_available(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        rows = self.cur.fetchmany(100)
        self.assertEqual(len(rows), 5)

    def test_fetchall(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        self.assertEqual(self.cur.fetchall(),
                         [(1,), (2,), (3,), (4,), (5,)])

    def test_fetchall_after_partial_fetch(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        self.cur.fetchone()
        self.assertEqual(self.cur.fetchall(),
                         [(2,), (3,), (4,), (5,)])

    # ----- iteration -----

    def test_iter_yields_all_rows(self):
        self._setup_rows()
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        seen = [row for row in self.cur]
        self.assertEqual(seen, [(1,), (2,), (3,), (4,), (5,)])

    # ----- NULL passthrough -----

    def test_null_values_in_row(self):
        self._setup_rows()
        self.cur.execute(
            f"SELECT name, score FROM {self.TABLE} WHERE id = 5"
        )
        self.assertEqual(self.cur.fetchone(), (None, None))

    # ----- context managers -----

    def test_cursor_context_manager_closes(self):
        with self.conn.cursor() as cur:
            cur.execute(
                f"CREATE TABLE {self.TABLE} (id NUMBER)"
            )
        # After the block the cursor must be closed.
        with self.assertRaises(oracle.InterfaceError):
            cur.execute("SELECT 1 FROM dual")

    # ----- error mapping -----

    def test_select_from_nonexistent_raises_942(self):
        with self.assertRaises(oracle.DatabaseError) as ctx:
            self.cur.execute(f"SELECT * FROM nope_{os.getpid()}_xyz")
        self.assertEqual(ctx.exception.code, 942)

    # ----- executemany (array DML) -----

    def test_executemany_insert(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(20))")
        rows = [(i, f"n{i}") for i in range(1, 21)]
        self.cur.executemany(f"INSERT INTO {self.TABLE} VALUES (:1, :2)", rows)
        self.assertEqual(self.cur.rowcount, 20)
        self.cur.execute(f"SELECT id, name FROM {self.TABLE} ORDER BY id")
        self.assertEqual(self.cur.fetchall(), rows)

    def test_executemany_single_round_trip(self):
        # The whole batch must go in one server round trip, not one per row.
        # Count only TNS_DATA sends: under XE's logon-storm throttle the server
        # can inject a break/marker mid-response, and the driver's marker ack is
        # an extra (non-data) send that would otherwise make this flake.
        from oracle.tns_consts import TNS_DATA
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        import oracle.connection as _c
        orig = _c.OracleConnect.send
        sends = [0]
        _c.OracleConnect.send = lambda s, T, D: (
            sends.__setitem__(0, sends[0] + (1 if T == TNS_DATA else 0)),
            orig(s, T, D))[1]
        try:
            self.cur.executemany(
                f"INSERT INTO {self.TABLE} VALUES (:1)", [(i,) for i in range(50)])
        finally:
            _c.OracleConnect.send = orig
        self.assertEqual(sends[0], 1)
        self.assertEqual(self.cur.rowcount, 50)

    def test_executemany_delete(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.executemany(
            f"INSERT INTO {self.TABLE} VALUES (:1)", [(i,) for i in range(10)])
        self.cur.executemany(
            f"DELETE FROM {self.TABLE} WHERE id = :1", [(2,), (4,), (6,)])
        self.assertEqual(self.cur.rowcount, 3)
        self.cur.execute(f"SELECT COUNT(*) FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (7,))

    def test_executemany_empty(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.executemany(f"INSERT INTO {self.TABLE} VALUES (:1)", [])
        self.assertEqual(self.cur.rowcount, 0)
        self.cur.execute(f"SELECT COUNT(*) FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (0,))

    def test_executemany_batcherrors(self):
        # With batcherrors=True a per-row constraint violation no longer aborts
        # the batch: good rows are applied and the failures are collected via
        # getbatcherrors() (#18).
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY, v VARCHAR2(10))")
        rows = [(1, "a"), (2, "b"), (1, "dup"), (3, "c"), (2, "dup2")]
        self.cur.executemany(
            f"INSERT INTO {self.TABLE} VALUES (:1, :2)", rows, batcherrors=True)
        errs = self.cur.getbatcherrors()
        self.assertEqual([(e.offset, e.code) for e in errs], [(2, 1), (4, 1)])
        self.assertIn("ORA-00001", str(errs[0]))
        # The non-violating rows were committed.
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        self.assertEqual([r[0] for r in self.cur.fetchall()], [1, 2, 3])

    def test_executemany_without_batcherrors_raises(self):
        # Default behaviour is unchanged: a constraint violation aborts and
        # raises rather than being collected.
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY)")
        with self.assertRaises(oracle.IntegrityError):
            self.cur.executemany(
                f"INSERT INTO {self.TABLE} VALUES (:1)", [(1,), (1,)])

    def test_getbatcherrors_empty_when_no_errors(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.executemany(
            f"INSERT INTO {self.TABLE} VALUES (:1)", [(1,), (2,)],
            batcherrors=True)
        self.assertEqual(self.cur.getbatcherrors(), [])

    # ----- executemany arraydmlrowcounts (12c+) -----

    def _require_12c(self):
        # arraydmlrowcounts is a 12.1+ server feature (it rides the 12c+ OALL8
        # al8pidmlrc block); skip the positive tests on an 11g server.
        from oracle.tns import FIELD_VERSION_12_1
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest("arraydmlrowcounts needs a 12.1+ server")

    def test_executemany_arraydmlrowcounts_update(self):
        # Per-iteration affected-row counts: UPDATE g=1 hits 3 rows, g=2 hits 1,
        # g=3 hits 2, g=9 hits none -> [3, 1, 2, 0]. Matches oracledb (#18).
        self._require_12c()
        self.cur.execute(f"CREATE TABLE {self.TABLE} (g NUMBER, v NUMBER)")
        self.cur.executemany(
            f"INSERT INTO {self.TABLE} VALUES (:1, :2)",
            [(1, 1), (1, 2), (2, 3), (1, 4), (3, 5), (3, 6)])
        self.cur.executemany(
            f"UPDATE {self.TABLE} SET v = v + 10 WHERE g = :1",
            [(1,), (2,), (3,), (9,)], arraydmlrowcounts=True)
        self.assertEqual(self.cur.getarraydmlrowcounts(), [3, 1, 2, 0])

    def test_executemany_arraydmlrowcounts_insert(self):
        # Each INSERT iteration affects exactly one row.
        self._require_12c()
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.executemany(
            f"INSERT INTO {self.TABLE} VALUES (:1)", [(i,) for i in range(5)],
            arraydmlrowcounts=True)
        self.assertEqual(self.cur.getarraydmlrowcounts(), [1, 1, 1, 1, 1])

    def test_arraydmlrowcounts_empty_without_request(self):
        # Without arraydmlrowcounts the list stays empty, and a prior request's
        # counts don't leak into a later plain executemany.
        self._require_12c()
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.executemany(
            f"INSERT INTO {self.TABLE} VALUES (:1)", [(1,), (2,)],
            arraydmlrowcounts=True)
        self.assertEqual(self.cur.getarraydmlrowcounts(), [1, 1])
        self.cur.executemany(
            f"INSERT INTO {self.TABLE} VALUES (:1)", [(3,), (4,)])
        self.assertEqual(self.cur.getarraydmlrowcounts(), [])

    def test_arraydmlrowcounts_unsupported_on_11g(self):
        # On an 11g server the feature is rejected up front (oracledb-compatible).
        from oracle.tns import FIELD_VERSION_12_1
        if self.conn.field_version >= FIELD_VERSION_12_1:
            self.skipTest("server supports arraydmlrowcounts")
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        with self.assertRaises(oracle.NotSupportedError):
            self.cur.executemany(
                f"INSERT INTO {self.TABLE} VALUES (:1)", [(1,), (2,)],
                arraydmlrowcounts=True)

    # ----- closed-state guards -----

    def test_fetch_without_execute_raises(self):
        with self.assertRaises(oracle.InterfaceError):
            self.cur.fetchone()

    def test_use_after_close_raises(self):
        self.cur.close()
        with self.assertRaises(oracle.InterfaceError):
            self.cur.execute("SELECT 1 FROM dual")


@unittest.skipUnless(_USER, _SKIP_REASON)
class BindIntegration(_IntegrationBase):
    """Verify Cursor.execute parameter binding."""

    # ----- positional binds -----

    def test_positional_int_string(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1, :2)", [7, "alpha"]
        )
        self.cur.execute(f"SELECT id, name FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(7, "alpha")])

    def test_positional_tuple_accepted(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1, :2)", (8, "beta")
        )
        self.cur.execute(f"SELECT id, name FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(8, "beta")])

    def test_varchar_supplementary_bind(self):
        # Binding a supplementary-plane string must encode real UTF-8 (the OAC
        # advertises AL32UTF8); otherwise the emoji corrupts on the way in (#29).
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v VARCHAR2(40))")
        val = "go 😀 端 🎉 stop"
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)", [val])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(val,)])

    def test_nvarchar_bind(self):
        # Bind into an NVARCHAR2 (national charset) column, including a
        # supplementary-plane character.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v NVARCHAR2(40))")
        val = "nat ünî 中 😀"
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)", [val])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(val,)])

    def test_national_char_var_bind(self):
        # Bind full Unicode into NVARCHAR2 via the national bind type (#174).
        # Works on every tier: 9i rides it natively as AL16UTF16, where a plain
        # str bind would route through the (non-Unicode) DB charset and lose
        # characters; 10g+ get the same csfrm-2 OAC.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v NVARCHAR2(40))")
        val = "café—Ω—日本"
        var = self.cur.var(oracle.DB_TYPE_NVARCHAR)
        var.setvalue(0, val)
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)", [var])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(val,)])

    def test_db_charset_varchar_roundtrip(self):
        # VARCHAR2 non-ASCII that the database charset can represent round-trips
        # (#174). On 9i (WE8ISO8859P1) the server converts the AL32UTF8 session
        # bytes to its Latin-1 DB charset and back; decoding by the column's DB
        # charset instead of the session charset used to mojibake it.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v VARCHAR2(40))")
        val = "café déjà vu"           # Latin-1-representable
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)", [val])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(val,)])

    def test_null_bind(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1, :2)", [9, None]
        )
        self.cur.execute(f"SELECT name FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(None,)])

    # ----- types -----

    def test_decimal_round_trip(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (v NUMBER(12, 4))"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1)", [Decimal("3.1415")]
        )
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (Decimal("3.1415"),))

    def test_integer_decimal_round_trips_as_int(self):
        # A Decimal with no fractional part comes back as int, not Decimal.
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (v NUMBER)"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1)", [Decimal("42")]
        )
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (42,))

    def test_date_round_trip(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (d DATE)")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1)",
            [datetime.datetime(2026, 5, 23, 10, 11, 12)],
        )
        self.cur.execute(f"SELECT d FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(),
                         (datetime.datetime(2026, 5, 23, 10, 11, 12),))

    def test_timestamp_round_trip(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (t TIMESTAMP)")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1)",
            [datetime.datetime(2026, 5, 23, 10, 11, 12, 345678)],
        )
        self.cur.execute(f"SELECT t FROM {self.TABLE}")
        self.assertEqual(
            self.cur.fetchone(),
            (datetime.datetime(2026, 5, 23, 10, 11, 12, 345678),),
        )

    def test_timestamptz_round_trip(self):
        Tz = datetime.timezone(datetime.timedelta(hours=-5, minutes=-30))
        Value = datetime.datetime(2026, 5, 23, 10, 11, 12, 345678, tzinfo=Tz)
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (t TIMESTAMP WITH TIME ZONE)"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1)", [Value]
        )
        self.cur.execute(f"SELECT t FROM {self.TABLE}")
        Got = self.cur.fetchone()[0]
        # The instant must match; the tagged offset must round-trip.
        self.assertEqual(Got, Value)
        self.assertEqual(Got.utcoffset(), Value.utcoffset())

    def test_binary_float_bind(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v BINARY_FLOAT)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)",
                         [oracle.BinaryFloat(-2.25)])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (-2.25,))

    def test_binary_double_bind(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v BINARY_DOUBLE)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)",
                         [oracle.BinaryDouble(1234.5678)])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (1234.5678,))

    def test_binary_double_nonfinite_bind(self):
        # inf / nan can't be NUMBER; a plain float auto-routes to BINARY_DOUBLE.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v BINARY_DOUBLE)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)", [float("inf")])
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)", [float("nan")])
        self.cur.execute(f"SELECT v FROM {self.TABLE} ORDER BY 1")
        rows = self.cur.fetchall()
        self.assertEqual(rows[0], (math.inf,))
        self.assertTrue(math.isnan(rows[1][0]))

    def test_interval_ds_bind(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (v INTERVAL DAY(4) TO SECOND(6))")
        Value = datetime.timedelta(days=5, hours=4, minutes=3, seconds=2,
                                   microseconds=123456)
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)", [Value])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (Value,))

    def test_interval_ym_bind(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (v INTERVAL YEAR(4) TO MONTH)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)",
                         [oracle.IntervalYM(3, 7)])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (oracle.IntervalYM(3, 7),))

    # ----- bind ordering (str before number) -----

    def test_str_before_number_bind(self):
        # A VARCHAR bind preceding a NUMBER bind used to be sized at 32767,
        # which the server treated as a LONG and reordered — silently swapping
        # the two binds. Both columns must round-trip correctly.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (a VARCHAR2(20), b NUMBER)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1, :2)", ["hi", 7])
        self.cur.execute(f"SELECT a, b FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), ("hi", 7))

    def test_update_set_str_where_number(self):
        # The classic failing shape: SET <string> WHERE <number>.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(20))")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 'orig')")
        self.cur.execute(
            f"UPDATE {self.TABLE} SET name = :1 WHERE id = :2", ["updated", 1])
        self.assertEqual(self.cur.rowcount, 1)
        self.cur.execute(f"SELECT name FROM {self.TABLE} WHERE id = 1")
        self.assertEqual(self.cur.fetchone(), ("updated",))

    def test_three_binds_str_in_middle(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (a NUMBER, b VARCHAR2(20), c NUMBER)")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1, :2, :3)", [11, "XX", 33])
        self.cur.execute(f"SELECT a, b, c FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (11, "XX", 33))

    # ----- PL/SQL blocks with binds -----

    def test_plsql_block_in_bind(self):
        # An anonymous PL/SQL block carrying a bind variable must execute
        # server-side (previously ORA-00600 [12259]). Prove the bound value
        # reached the block by having it insert the value.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v NUMBER)")
        self.cur.execute(
            f"BEGIN INSERT INTO {self.TABLE} VALUES (:x); END;", [42])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (42,))

    def test_plsql_block_mixed_binds(self):
        # Issue #13: a VARCHAR + NUMBER bind in an UPDATE inside a PL/SQL block
        # used to raise ORA-00600 [12259]. Must run and update the row.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(100))")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, NULL)")
        self.cur.execute(
            f"BEGIN UPDATE {self.TABLE} SET v = :a WHERE id = :b; END;",
            {"a": "hi", "b": 1})
        self.cur.execute(f"SELECT v FROM {self.TABLE} WHERE id = 1")
        self.assertEqual(self.cur.fetchone(), ("hi",))

    def test_plsql_block_two_in_binds(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v NUMBER)")
        self.cur.execute(
            f"BEGIN INSERT INTO {self.TABLE} VALUES (:a + :b); END;", [3, 4])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (7,))

    # ----- named binds -----

    def test_named_dict_binds(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:id, :name)",
            {"id": 10, "name": "named"},
        )
        self.cur.execute(f"SELECT id, name FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(10, "named")])

    def test_named_binds_are_case_insensitive(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        # Mixed case on both sides; bind names normalised lower-case.
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:ID, :Name)",
            {"id": 11, "NAME": "case"},
        )
        self.cur.execute(f"SELECT id, name FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(11, "case")])

    def test_named_binds_repeated_placeholder(self):
        # `:x` referenced twice in the SQL — the same value gets bound to
        # each textual occurrence. Each occurrence is a distinct bind
        # position on the wire (Oracle expects N OAC + N RXD entries for
        # N placeholder occurrences in plain SQL), but the caller only
        # has to provide one mapping.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (a NUMBER, b NUMBER)")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:x, :x)", {"x": 42}
        )
        self.cur.execute(f"SELECT a, b FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(42, 42)])

    def test_named_binds_repeated_in_predicate(self):
        # Reproducer from issue #15: `:x` referenced twice in a WHERE
        # clause used to trip ORA-01008 ("not all variables bound")
        # because the resolver deduplicated by name and only sent one
        # bind value where Oracle wanted two.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (2)")
        # Match-on-value
        self.cur.execute(
            f"SELECT id FROM {self.TABLE} WHERE id = :x OR :x IS NULL",
            {"x": 1},
        )
        self.assertEqual(self.cur.fetchall(), [(1,)])
        # Match-on-NULL: `:x IS NULL` triggers the second branch and
        # returns every row regardless of value.
        self.cur.execute(
            f"SELECT id FROM {self.TABLE} WHERE id = :x OR :x IS NULL",
            {"x": None},
        )
        self.assertEqual(sorted(self.cur.fetchall()), [(1,), (2,)])

    def test_named_binds_missing_key_raises(self):
        # ProgrammingError is the right slot in the PEP 249 hierarchy for
        # "the caller supplied bad inputs".
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        with self.assertRaises(oracle.ProgrammingError):
            self.cur.execute(
                f"INSERT INTO {self.TABLE} VALUES (:id, :name)",
                {"id": 12},   # missing :name
            )

    # ----- type validation -----

    def test_bad_parameters_type_raises(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        with self.assertRaises(oracle.NotSupportedError):
            self.cur.execute(
                f"INSERT INTO {self.TABLE} VALUES (:1)", "not-a-sequence"
            )

    # ----- SELECT with binds -----

    def test_select_with_bind_filter(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        for Row in [(1, "a"), (2, "b"), (3, "c")]:
            self.cur.execute(
                f"INSERT INTO {self.TABLE} VALUES (:1, :2)", list(Row)
            )
        self.cur.execute(
            f"SELECT name FROM {self.TABLE} WHERE id = :1", [2]
        )
        self.assertEqual(self.cur.fetchall(), [("b",)])

    def test_select_with_named_bind(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:1, :2)", [5, "five"]
        )
        self.cur.execute(
            f"SELECT name FROM {self.TABLE} WHERE id = :target",
            {"target": 5},
        )
        self.assertEqual(self.cur.fetchall(), [("five",)])

    # ----- safety: literal colons in strings shouldn't confuse bind parsing -----

    def test_colon_inside_string_literal_is_not_a_bind(self):
        # The SQL contains a `:not_a_bind` inside a quoted string. The bind
        # extractor must ignore it; only the real :v should require a value.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v VARCHAR2(40))")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES ('hello :not_a_bind ' || :v)",
            {"v": "world"},
        )
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(
            self.cur.fetchall(),
            [("hello :not_a_bind world",)],
        )


@unittest.skipUnless(_USER, _SKIP_REASON)
class TempLobBindIntegration(_IntegrationBase):
    """Large CLOB / BLOB into a PL/SQL locator param (#91).

    A str / bytes bind over the 32767-byte PL/SQL limit can't go through the
    streamed path (ORA-01460). The driver transparently routes it through a
    server temp LOB (CREATE_TEMP -> WRITE -> bind locator). 12c+ only — 11g
    rejects CREATE_TEMP, so the feature is gated and large PL/SQL binds keep
    their prior (ORA-01460) behaviour there.
    """

    def setUp(self):
        super().setUp()
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest("temp-LOB bind needs a 12c+ server (CREATE_TEMP)")
        self.cur.execute(
            "CREATE OR REPLACE FUNCTION pyo_clob_len(p CLOB) RETURN NUMBER IS "
            "BEGIN RETURN DBMS_LOB.GETLENGTH(p); END;")
        self.cur.execute(
            "CREATE OR REPLACE FUNCTION pyo_blob_len(p BLOB) RETURN NUMBER IS "
            "BEGIN RETURN DBMS_LOB.GETLENGTH(p); END;")

    def test_large_clob_bind(self):
        for n in (40000, 100000, 500000):
            r = self.cur.var(oracle.NUMBER)
            self.cur.execute("BEGIN :r := pyo_clob_len(:p); END;",
                             {"r": r, "p": "X" * n})
            self.assertEqual(r.getvalue(), n)

    def test_large_blob_bind(self):
        for n in (40000, 100000, 300000):
            r = self.cur.var(oracle.NUMBER)
            self.cur.execute("BEGIN :r := pyo_blob_len(:p); END;",
                             {"r": r, "p": b"\xab" * n})
            self.assertEqual(r.getvalue(), n)

    def test_small_bind_unaffected(self):
        # Values within the PL/SQL limit keep the regular streamed path.
        for n in (10, 100, 30000):
            r = self.cur.var(oracle.NUMBER)
            self.cur.execute("BEGIN :r := pyo_clob_len(:p); END;",
                             {"r": r, "p": "Y" * n})
            self.assertEqual(r.getvalue(), n)

    def test_repeated_mixed_sizes_stay_synced(self):
        # The temp-LOB ops are interleaved with the execute; a stale OER scan
        # used to desync the next write. Exercise the alternating path.
        for n in (100, 100000, 30000, 200000, 50):
            r = self.cur.var(oracle.NUMBER)
            self.cur.execute("BEGIN :r := pyo_clob_len(:p); END;",
                             {"r": r, "p": "Z" * n})
            self.assertEqual(r.getvalue(), n)


@unittest.skipUnless(_USER, _SKIP_REASON)
class ErrorAndRowcountIntegration(_IntegrationBase):
    """Verify that DatabaseError carries the server's message text and that
    Cursor.rowcount reflects the affected-row count from the OER block."""

    def test_error_message_includes_ora_text(self):
        with self.assertRaises(oracle.DatabaseError) as ctx:
            self.cur.execute(f"SELECT * FROM nope_{os.getpid()}_xyz")
        # Exception code: the ORA number; str(): the full server message.
        self.assertEqual(ctx.exception.code, 942)
        self.assertIn("ORA-00942", str(ctx.exception))
        # Assert the message fragments separately: 23ai+ embeds the object name
        # (table or view "PYO"."NOPE…" does not exist), so the literal
        # "table or view does not exist" no longer appears as one substring.
        self.assertIn("table or view", str(ctx.exception))
        self.assertIn("does not exist", str(ctx.exception))

    def test_error_message_for_invalid_number(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        with self.assertRaises(oracle.DatabaseError) as ctx:
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('not-a-number')")
        # The ORA-01722 code is the stable contract; the English text varies by
        # version (11g/21c: "invalid number"; 23ai: "unable to convert string
        # value … to a number"), so assert on the code + prefix, not the phrase.
        self.assertEqual(ctx.exception.code, 1722)
        self.assertIn("ORA-01722", str(ctx.exception))

    def test_error_message_for_unique_constraint(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY)"
        )
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1)")
        with self.assertRaises(oracle.DatabaseError) as ctx:
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1)")
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("ORA-00001", str(ctx.exception))
        self.assertIn("unique constraint", str(ctx.exception))

    # ----- PEP 249 exception subclass dispatch -----

    def test_unique_constraint_raises_integrity_error(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER PRIMARY KEY)"
        )
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1)")
        with self.assertRaises(oracle.IntegrityError):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1)")

    def test_invalid_number_raises_data_error(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        with self.assertRaises(oracle.DataError):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('not-a-number')")

    def test_missing_table_raises_programming_error(self):
        with self.assertRaises(oracle.ProgrammingError):
            self.cur.execute(f"SELECT * FROM nope_{os.getpid()}_xyz")

    def test_subclass_still_catchable_as_database_error(self):
        # All the subclasses inherit from DatabaseError, so existing
        # callers that catch the base class keep working.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        with self.assertRaises(oracle.DatabaseError):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('not-a-number')")

    def test_rowcount_insert_single(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1)")
        self.assertEqual(self.cur.rowcount, 1)

    def test_rowcount_update_affecting_multiple(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        for n in (1, 2, 3, 4):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ({n})")
        self.cur.execute(f"UPDATE {self.TABLE} SET id = id + 10 WHERE id <= 3")
        self.assertEqual(self.cur.rowcount, 3)

    def test_rowcount_update_no_match(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1)")
        self.cur.execute(f"UPDATE {self.TABLE} SET id = 99 WHERE id > 1000")
        self.assertEqual(self.cur.rowcount, 0)

    def test_rowcount_delete(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        for n in (1, 2, 3):
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ({n})")
        self.cur.execute(f"DELETE FROM {self.TABLE} WHERE id < 3")
        self.assertEqual(self.cur.rowcount, 2)

    def test_rowcount_ddl_is_zero(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.assertEqual(self.cur.rowcount, 0)


@unittest.skipUnless(_USER, _SKIP_REASON)
class CursorCacheIntegration(_IntegrationBase):
    """Verify the cursor cache hands out a non-zero handle on the first
    DML execute and reuses it (with a smaller wire request) on repeats."""

    def _cached_handle(self, sql):
        # The cursor cache is keyed on (SQL text, bind-OAC signature), not the
        # bare SQL, so look up by the SQL component of the tuple keys.
        handles = [v for k, v in self.conn._cursor_cache.items() if k[0] == sql]
        return handles[0] if handles else None

    def test_repeated_dml_reuses_cursor(self):
        if self.conn.field_version >= FIELD_VERSION_12_1:
            # The cache is disabled on the *negotiated* 12c+ connection, so gate
            # on that — not on PYORACLE_TEST_FIELD_VERSION, which is unset when
            # the suite simply points at a 21c server (#81).
            self.skipTest("cursor cache is disabled on 12c+ (re-parse each execute)")
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(10))")
        Sql = f"INSERT INTO {self.TABLE} VALUES (:id, :v)"
        # First execute: parses + caches.
        self.cur.execute(Sql, {"id": 1, "v": "a"})
        FirstCursor = self._cached_handle(Sql)
        self.assertIsNotNone(FirstCursor)
        self.assertGreater(FirstCursor, 0)
        # Second execute of identical SQL (same bind shape): same cached handle.
        self.cur.execute(Sql, {"id": 2, "v": "b"})
        self.assertEqual(self._cached_handle(Sql), FirstCursor)
        # Different SQL → different cache entry.
        Sql2 = f"UPDATE {self.TABLE} SET v = :v WHERE id = 1"
        self.cur.execute(Sql2, {"v": "z"})
        self.assertIsNotNone(self._cached_handle(Sql2))
        self.assertNotEqual(self._cached_handle(Sql), self._cached_handle(Sql2))
        # And the rows are what we expect.
        self.cur.execute(f"SELECT id, v FROM {self.TABLE} ORDER BY id")
        self.assertEqual(self.cur.fetchall(), [(1, "z"), (2, "b")])

    def test_cache_does_not_apply_to_select(self):
        # SELECT cache is intentionally skipped — caching a SELECT would
        # also need to remember the row format from the first DCB. Make
        # sure repeat SELECT works (i.e., we re-parse cleanly each time)
        # and that the cache stays SELECT-free.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (2)")
        Sql = f"SELECT id FROM {self.TABLE} WHERE id = :x"
        self.cur.execute(Sql, {"x": 1})
        self.assertEqual(self.cur.fetchall(), [(1,)])
        self.cur.execute(Sql, {"x": 2})
        self.assertEqual(self.cur.fetchall(), [(2,)])
        self.assertNotIn(Sql, self.conn._cursor_cache)

    def test_cache_evicts_oldest_when_full(self):
        if self.conn.field_version >= FIELD_VERSION_12_1:   # cache off on 12c+ (#81)
            self.skipTest("cursor cache is disabled on 12c+ (re-parse each execute)")
        # Drive past `_cursor_cache_max` distinct DML statements and
        # confirm the cache stays bounded and keeps the most recent.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        Max = self.conn._cursor_cache_max
        for i in range(Max + 5):
            # Each statement text is distinct, so each occupies its own
            # cache slot rather than sharing a handle.
            self.cur.execute(
                f"INSERT INTO {self.TABLE} /*{i}*/ VALUES ({i})"
            )
        self.assertEqual(len(self.conn._cursor_cache), Max)
        # The most recent insert's SQL must still be cached; the
        # earliest ones must have been evicted.
        Latest = f"INSERT INTO {self.TABLE} /*{Max + 4}*/ VALUES ({Max + 4})"
        Earliest = f"INSERT INTO {self.TABLE} /*0*/ VALUES (0)"
        CachedSql = {k[0] for k in self.conn._cursor_cache}
        self.assertIn(Latest, CachedSql)
        self.assertNotIn(Earliest, CachedSql)


@unittest.skipUnless(_USER, _SKIP_REASON)
class FetchFlowIntegration(_IntegrationBase):
    """Verify the follow-up TTI_FETCH flow.

    When a SELECT result set exceeds the per-call fetch size, the server
    returns the first N rows inline plus OER.call_status == 1 ("more on
    this cursor"). The driver must then issue TTI_FETCH against the open
    cursor until the server signals ORA-01403 (end of fetch).
    """

    def _populate(self, num_rows: int):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(40))"
        )
        for n in range(1, num_rows + 1):
            self.cur.execute(
                f"INSERT INTO {self.TABLE} VALUES (:1, :2)", [n, f"row{n}"]
            )

    def test_select_within_fetch_size(self):
        # 3 rows, default fetch (15) — single round-trip, no follow-up needed.
        self._populate(3)
        self.cur.execute(f"SELECT id, name FROM {self.TABLE} ORDER BY id")
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 3)
        self.assertEqual([r[0] for r in rows], [1, 2, 3])

    def test_select_spans_multiple_fetches(self):
        # 50 rows with fetch=7 → 8 round-trips (1 EXEC + 7 FETCH).
        self._populate(50)
        self.conn.fetch = 7
        self.cur.execute(f"SELECT id, name FROM {self.TABLE} ORDER BY id")
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 50)
        self.assertEqual([r[0] for r in rows], list(range(1, 51)))
        self.assertEqual(rows[-1], (50, "row50"))

    def test_select_exactly_one_fetch_boundary(self):
        # Row count exactly equal to fetch size — boundary case where the
        # server may or may not signal "more available" on the initial EXEC.
        self._populate(7)
        self.conn.fetch = 7
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        rows = self.cur.fetchall()
        self.assertEqual([r[0] for r in rows], list(range(1, 8)))

    def test_select_empty_table(self):
        # Zero-row SELECT — the FETCH loop must not fire.
        self._populate(0)
        self.cur.execute(f"SELECT id FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [])

    def test_scroll_over_buffered_result(self):
        # Cursor.scroll (issue #19) over a result set that spans several
        # server fetches — the whole set is buffered, so scroll repositions
        # locally in any direction.
        self._populate(20)
        self.conn.fetch = 6
        self.cur.execute(f"SELECT id, name FROM {self.TABLE} ORDER BY id")
        self.cur.scroll(mode="last")
        self.assertEqual(self.cur.fetchone(), (20, "row20"))
        self.cur.scroll(10, mode="absolute")
        self.assertEqual(self.cur.fetchone(), (10, "row10"))
        self.cur.scroll(-5, mode="relative")            # from row 10 -> row 5
        self.assertEqual(self.cur.fetchone(), (5, "row5"))
        self.cur.scroll(mode="first")
        self.assertEqual(self.cur.fetchone(), (1, "row1"))
        with self.assertRaises(IndexError):
            self.cur.scroll(999, mode="absolute")

    def test_scrollable_cursor(self):
        # Scrollable cursor (#161, oracledb parity): cursor(scrollable=True) +
        # the .scrollable property + scroll in every mode.
        self._populate(10)
        sc = self.conn.cursor(scrollable=True)
        self.assertIs(sc.scrollable, True)
        self.assertIs(self.conn.cursor().scrollable, False)
        sc.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        sc.scroll(5, mode="absolute")
        self.assertEqual(sc.fetchone(), (5,))
        sc.scroll(-2, mode="relative")
        self.assertEqual(sc.fetchone(), (3,))
        sc.scroll(mode="last")
        self.assertEqual(sc.fetchone(), (10,))
        sc.scroll(mode="first")
        self.assertEqual(sc.fetchone(), (1,))

    def test_scrollable_lazy_fetch_on_demand(self):
        # Server-side scrollable cursor (#181), 10g+: rows are pulled lazily from
        # a kept-open cursor in arraysize batches (here prefetchrows=2,
        # arraysize=3 over 10 rows forces several positioned re-executes), and
        # scroll() repositions server-side. 9i has no OALL8 scroll and falls back
        # to the buffered path (covered by test_scrollable_cursor).
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest("server-side scroll needs 10g+ (9i uses buffered scroll)")
        self._populate(10)
        sc = self.conn.cursor(scrollable=True)
        sc.prefetchrows = 2
        sc.arraysize = 3
        sc.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        self.assertTrue(sc._scroll_active)              # lazy path engaged
        # fetch-on-demand across batch boundaries
        self.assertEqual([r[0] for r in sc.fetchmany(5)], [1, 2, 3, 4, 5])
        sc.scroll(8, mode="absolute")
        self.assertEqual([r[0] for r in sc.fetchall()], [8, 9, 10])
        sc.scroll(mode="first")
        self.assertEqual([r[0] for r in sc.fetchall()], list(range(1, 11)))

    def test_scrollable_scroll_off_end_and_back(self):
        # Scrolling past the end (#181) leaves the cursor empty (next fetchone is
        # None), and a later scroll repositions back into the result set.
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest("server-side scroll needs 10g+")
        self._populate(5)
        sc = self.conn.cursor(scrollable=True)
        sc.prefetchrows = 2
        sc.arraysize = 2
        sc.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        sc.scroll(99, mode="absolute")
        self.assertIsNone(sc.fetchone())
        sc.scroll(mode="first")
        self.assertEqual(sc.fetchone(), (1,))

    def test_scrollable_last_after_eof_duplicate_value(self):
        # LAST after the buffer already reached EOF with arraysize >= row count
        # (#181): the server repositions onto the last row, whose value equals the
        # one just returned, so it omits the value and flags "reuse previous" in
        # the row-header bit vector. Exercises decode_token_rxh's bit-vector pass
        # + the previous-row seed (this used to desync / crash on token 0x0a).
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest("server-side scroll needs 10g+")
        self._populate(6)
        sc = self.conn.cursor(scrollable=True)
        sc.prefetchrows = 2
        sc.arraysize = 50                              # >= row count
        sc.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        sc.scroll(mode="first")
        self.assertEqual([r[0] for r in sc.fetchall()], list(range(1, 7)))
        sc.scroll(mode="last")
        self.assertEqual(sc.fetchone(), (6,))          # correct value, no crash

    def test_fetch_df_all_and_batches(self):
        # Arrow / DataFrame bulk fetch (#162): fetch_df_all returns a
        # pyarrow.Table column-major; fetch_df_batches streams it in chunks.
        import pyarrow as pa
        self._populate(7)
        self.cur.execute(f"SELECT id, name FROM {self.TABLE} ORDER BY id")
        table = self.cur.fetch_df_all()
        self.assertIsInstance(table, pa.Table)
        self.assertEqual(table.num_rows, 7)
        self.assertEqual([c.upper() for c in table.column_names], ["ID", "NAME"])
        self.assertEqual(table.column("ID").to_pylist(), list(range(1, 8)))
        self.assertEqual(table.column("NAME").to_pylist(),
                         [f"row{i}" for i in range(1, 8)])
        # batches of 3 -> 3 + 3 + 1
        self.cur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        sizes = [b.num_rows for b in self.cur.fetch_df_batches(size=3)]
        self.assertEqual(sizes, [3, 3, 1])
        # empty result keeps a usable schema
        self.cur.execute(f"SELECT id, name FROM {self.TABLE} WHERE id > 999")
        empty = self.cur.fetch_df_all()
        self.assertEqual(empty.num_rows, 0)
        self.assertEqual(len(empty.column_names), 2)

    def test_end_to_end_tracing(self):
        # End-to-end application tracing (#183): set module / action /
        # client_identifier; the change flushes with the next execute and shows
        # up in SYS_CONTEXT('USERENV', ...). 12c+ only (the piggyback closes a
        # pre-12c connection), so pre-12c must raise NotSupportedError instead.
        if self.conn.field_version < FIELD_VERSION_12_1:
            with self.assertRaises(oracle.NotSupportedError):
                self.conn.module = "M"
            return
        self.conn.module = "PYOMOD"
        self.conn.action = "PYOACT"
        self.conn.client_identifier = "PYOCLID"
        self.assertEqual(self.conn.module, "PYOMOD")
        self.cur.execute(
            "SELECT SYS_CONTEXT('USERENV','MODULE'), "
            "SYS_CONTEXT('USERENV','ACTION'), "
            "SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') FROM dual")
        self.assertEqual(self.cur.fetchone(), ("PYOMOD", "PYOACT", "PYOCLID"))
        # changing only one updates just that attribute
        self.conn.action = "ACT2"
        self.cur.execute(
            "SELECT SYS_CONTEXT('USERENV','ACTION'), "
            "SYS_CONTEXT('USERENV','MODULE') FROM dual")
        self.assertEqual(self.cur.fetchone(), ("ACT2", "PYOMOD"))
        # clientinfo (#184) shows in USERENV.CLIENT_INFO.
        self.conn.clientinfo = "PYOINFO"
        self.cur.execute(
            "SELECT SYS_CONTEXT('USERENV','CLIENT_INFO') FROM dual")
        self.assertEqual(self.cur.fetchone(), ("PYOINFO",))
        self.assertEqual(self.conn.clientinfo, "PYOINFO")
        # dbop (#184) is monitored via V$SQL_MONITOR (not USERENV); just confirm
        # the piggyback is accepted and the connection stays usable.
        self.conn.dbop = "PYODBOP"
        self.cur.execute("SELECT 1 FROM dual")
        self.assertEqual(self.cur.fetchone(), (1,))
        self.assertEqual(self.conn.dbop, "PYODBOP")

    def test_module_alone(self):
        # Setting module without action must not malform the piggyback — Oracle
        # requires both together, so a module-only flush carries action too
        # (#184). 12c+ only.
        if self.conn.field_version < FIELD_VERSION_12_1:
            self.skipTest("end-to-end tracing requires 12c+")
        self.conn.module = "SOLOMOD"
        self.cur.execute("SELECT SYS_CONTEXT('USERENV','MODULE') FROM dual")
        self.assertEqual(self.cur.fetchone(), ("SOLOMOD",))

    def test_repeated_execute_no_cursor_leak(self):
        # #191: repeated execute() of one statement must not leak server
        # cursors. Pre-fix this tripped ORA-01000 after ~300 executes on 12c+
        # (cache off); the drained cursor is now freed by an OCCA piggyback in
        # front of the next call. 400 > the typical OPEN_CURSORS, so this would
        # fail on 12c+ without the fix.
        if self.conn.field_version < FIELD_VERSION_10_2:
            self.skipTest("fv2 (9i) uses a separate execute path")
        t = "PYO_LEAK191"
        try:
            self.cur.execute(f"DROP TABLE {t}")
        except oracle.DatabaseError:
            # table may not exist; drop is best-effort cleanup
            pass
        self.cur.execute(f"CREATE TABLE {t} (id NUMBER)")
        try:
            for i in range(400):
                self.cur.execute(f"INSERT INTO {t} VALUES (:1)", [i])
            self.conn.commit()
            self.cur.execute(f"SELECT COUNT(*) FROM {t}")
            self.assertEqual(self.cur.fetchone()[0], 400)
        finally:
            self.cur.execute(f"DROP TABLE {t}")


@unittest.skipUnless(_USER, _SKIP_REASON)
class LOBIntegration(_IntegrationBase):
    """Verify LOB column read + content extraction.

    NULL LOBs surface as Python None. EMPTY_CLOB() / EMPTY_BLOB() come
    back as `""` / `b""`. Non-empty small LOBs whose content fits inside
    the inline section of the locator block round-trip as `str` (CLOB) or
    `bytes` (BLOB). Out-of-line content (large LOBs that overflow the
    inline budget) needs a TTI_LOBOPS round-trip the driver doesn't yet
    issue — see the README's "still in progress" list.
    """

    def _setup(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, c CLOB, b BLOB)"
        )

    def test_null_lobs_are_none(self):
        self._setup()
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, NULL, NULL)")
        self.cur.execute(f"SELECT id, c, b FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (1, None, None))

    def test_empty_lobs_are_empty_str_or_bytes(self):
        self._setup()
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, EMPTY_CLOB(), EMPTY_BLOB())"
        )
        self.cur.execute(f"SELECT c, b FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), ("", b""))

    def test_clob_content_round_trip(self):
        self._setup()
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, 'hello clob', NULL)"
        )
        self.cur.execute(f"SELECT c FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), ("hello clob",))

    def test_blob_content_round_trip(self):
        self._setup()
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, NULL, HEXTORAW('DEADBEEF'))"
        )
        self.cur.execute(f"SELECT b FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (b"\xde\xad\xbe\xef",))

    def test_blob_with_non_ascii_high_bytes(self):
        # Includes a byte (0xCA) that's outside ASCII so we'd notice if the
        # decoder accidentally tried to decode the BLOB as text.
        self._setup()
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES "
            f"(1, NULL, HEXTORAW('CAFEBABE0123'))"
        )
        self.cur.execute(f"SELECT b FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(),
                         (b"\xca\xfe\xba\xbe\x01\x23",))

    def test_clob_with_longer_content(self):
        self._setup()
        Text = "longer text content here"
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, '{Text}', NULL)"
        )
        self.cur.execute(f"SELECT c FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (Text,))

    def test_multiple_rows_with_lobs(self):
        # Walks the row decoder across several rows so any byte-count
        # mistake in the LOB reader would derail the next row.
        self._setup()
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, NULL, NULL)")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (2, EMPTY_CLOB(), EMPTY_BLOB())"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (3, 'three', HEXTORAW('A1'))"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES "
            f"(4, 'four bytes more', HEXTORAW('1234567890ABCDEF'))"
        )
        self.cur.execute(f"SELECT id, c, b FROM {self.TABLE} ORDER BY id")
        rows = self.cur.fetchall()
        self.assertEqual(rows, [
            (1, None, None),
            (2, "", b""),
            (3, "three", b"\xa1"),
            (4, "four bytes more",
             b"\x12\x34\x56\x78\x90\xab\xcd\xef"),
        ])

    def test_lob_alongside_other_columns(self):
        # Mix a LOB with surrounding non-LOB columns so we exercise the
        # decoder's transition into and out of the LOB code path.
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} "
            f"(prefix VARCHAR2(10), c CLOB, suffix NUMBER)"
        )
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES ('alpha', 'middle clob', 42)"
        )
        self.cur.execute(f"SELECT prefix, c, suffix FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(),
                         ("alpha", "middle clob", 42))

    def test_clob_larger_than_inline_budget(self):
        # A CLOB whose content makes the locator+inline section big enough
        # that Oracle would normally not pack it inline. We can't tell from
        # the client side whether the server chose inline or out-of-line
        # storage; what matters is that the TTI_LOBOPS round-trip in
        # LOB.read() returns the full content either way.
        self._setup()
        Text = "abcdefghij" * 200            # 2000 chars, fits in a SQL literal
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, c) VALUES (1, '{Text}')"
        )
        self.cur.execute(f"SELECT c FROM {self.TABLE}")
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Text))
        self.assertEqual(Got, Text)

    def test_clob_bind_above_varchar2_cap(self):
        # SQL VARCHAR2 binds top out at 4000 bytes. Anything bigger used
        # to trip ORA-01461 ("can bind a LONG value only for insert into a
        # LONG column"). The bind OAC now declares max_size = 32767 so
        # multi-KiB CLOB binds reach the column.
        self._setup()
        Text = "abcdefghij" * 700            # 7000 chars
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)", {"c": Text}
        )
        self.cur.execute(f"SELECT c FROM {self.TABLE}")
        (Got,) = self.cur.fetchone()
        self.assertEqual(Got, Text)

    def test_clob_bind_spans_multiple_packets(self):
        # A bind whose request exceeds the SDU (default 8 KiB) must be split
        # across multiple TNS_DATA packets (non-final fragments carry data
        # flags 0x0020). 20 KiB → ~3 fragments; kept under the 32767 regular-
        # bind ceiling so it round-trips on both 11g and 12c+ (issue #8).
        self._setup()
        Text = "0123456789abcdef" * 1250        # 20000 chars, > 2x SDU
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)", {"c": Text}
        )
        self.cur.execute(f"SELECT c FROM {self.TABLE}")
        (Got,) = self.cur.fetchone()
        self.assertEqual(Got, Text)

    def test_blob_bind_round_trip_all_byte_values(self):
        # Two things at once: bytes binds used to be decoded as UTF-8 and
        # re-encoded as UTF-16BE — which corrupted anything outside ASCII
        # and outright crashed on 0x80+ bytes — and they used to share the
        # 4000-byte VARCHAR2 cap. Now they're bound as RAW with the same
        # 32767-byte ceiling. This payload exercises every possible byte
        # value and is past the old cap.
        self._setup()
        Payload = bytes(range(256)) * 25     # 6400 bytes
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, b) VALUES (1, :b)", {"b": Payload}
        )
        self.cur.execute(f"SELECT b FROM {self.TABLE}")
        (Got,) = self.cur.fetchone()
        self.assertEqual(Got, Payload)

    # --- Very large LOB binds (#14) -------------------------------------
    #
    # A bind larger than the 32767-byte regular ceiling is streamed to the
    # server as a chunked LONG value and lands in the CLOB / BLOB column. The
    # request itself spans many TNS packets, so this also leans on the request
    # fragmentation fix (#8). These exercise the issue's acceptance sizes
    # (50 KiB and 500 KiB) for both LOB types, byte-for-byte, on 11g and 12c+.

    def test_clob_bind_50kib(self):
        self._setup()
        Text = "0123456789abcdef" * (50 * 1024 // 16)   # 51200 chars
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)", {"c": Text}
        )
        self.cur.execute(f"SELECT c FROM {self.TABLE}")
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Text))
        self.assertEqual(Got, Text)

    def test_clob_bind_500kib(self):
        self._setup()
        Text = "0123456789abcdef" * (500 * 1024 // 16)  # 512000 chars
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)", {"c": Text}
        )
        self.cur.execute(f"SELECT c FROM {self.TABLE}")
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Text))
        self.assertEqual(Got, Text)

    def test_blob_bind_50kib(self):
        self._setup()
        Payload = bytes(range(256)) * 200    # 51200 bytes, every byte value
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, b) VALUES (1, :b)", {"b": Payload}
        )
        self.cur.execute(f"SELECT b FROM {self.TABLE}")
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Payload))
        self.assertEqual(Got, Payload)

    def test_blob_bind_500kib(self):
        self._setup()
        Payload = bytes(range(256)) * 2000   # 512000 bytes, every byte value
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, b) VALUES (1, :b)", {"b": Payload}
        )
        self.cur.execute(f"SELECT b FROM {self.TABLE}")
        (Got,) = self.cur.fetchone()
        self.assertEqual(len(Got), len(Payload))
        self.assertEqual(Got, Payload)

    def test_clob_inline_chunked_locator(self):
        # A CLOB whose content is woven inline into the locator block can push
        # that block past 254 bytes, where it switches to the 0xFE chunked DALC
        # form. The row decoder must read the block as a DALC, not as a 1-byte
        # size echo + raw bytes (#37). 400 chars lands in that band.
        self._setup()
        Text = "abcd" * 100
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)", {"c": Text}
        )
        self.cur.execute(f"SELECT c FROM {self.TABLE} WHERE id=1")
        self.assertEqual(self.cur.fetchone()[0], Text)

    def test_nclob_round_trip(self):
        # NCLOB (national-charset LOB). Its inline content is UTF-16BE, so the
        # locator block crosses the 254-byte chunked-DALC threshold at half the
        # character count of a CLOB — the case #37 reported as broken on 11g.
        # Cover small, the chunked band, and supplementary-plane content.
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, nc NCLOB)"
        )
        Cases = {
            1: "national ünî 中",
            2: "B" * 200,
            3: "nclob ünî 中 😀🎉 " * 80,
        }
        for Id, Text in Cases.items():
            self.cur.execute(
                f"INSERT INTO {self.TABLE}(id, nc) VALUES (:i, :t)",
                {"i": Id, "t": Text},
            )
        for Id, Text in Cases.items():
            self.cur.execute(f"SELECT nc FROM {self.TABLE} WHERE id=:i",
                             {"i": Id})
            self.assertEqual(self.cur.fetchone()[0], Text)

    def test_error_then_large_lob_stays_synced(self):
        # #45: an errored call leaves the server's break/reset markers on the
        # wire; mishandling them (replying to every marker) storms the line and
        # discards the next response's data, so a large CLOB read right after a
        # few errors came back empty. Interleave errored SELECTs with a 50 KB
        # CLOB read and assert the content is intact and the connection usable.
        from oracle.exceptions import DatabaseError
        self._setup()
        Big = "A" * 50000
        self.cur.execute(
            f"INSERT INTO {self.TABLE}(id, c) VALUES (1, :c)", {"c": Big})
        self.conn.commit()
        for _ in range(8):
            with self.assertRaises(DatabaseError):
                self.cur.execute("SELECT * FROM pyoracle_no_such_table_45")
                self.cur.fetchall()
            self.cur.execute(f"SELECT c FROM {self.TABLE} WHERE id=1")
            (Got,) = self.cur.fetchone()
            self.assertEqual(len(Got), len(Big))
            self.assertEqual(Got, Big)


@unittest.skipUnless(_USER, _SKIP_REASON)
class BooleanIntegration(_IntegrationBase):
    # Native SQL BOOLEAN columns, 23ai+ (#54, TNS type 252). Skipped on servers
    # without the type (21c/11g reject the column with ORA-00902).
    def _setup_bool(self):
        from oracle.exceptions import DatabaseError
        try:
            self.cur.execute(
                f"CREATE TABLE {self.TABLE} (id NUMBER, flag BOOLEAN)")
        except DatabaseError as exc:
            if exc.code == 902:        # ORA-00902: invalid datatype (pre-23ai)
                self.skipTest("native BOOLEAN type needs a 23ai+ server")
            raise

    def test_boolean_decode(self):
        self._setup_bool()
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, TRUE)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (2, FALSE)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (3, NULL)")
        self.conn.commit()
        self.cur.execute(f"SELECT id, flag FROM {self.TABLE} ORDER BY id")
        rows = self.cur.fetchall()
        self.assertEqual(rows, [(1, True), (2, False), (3, None)])
        self.assertIsInstance(rows[0][1], bool)

    def test_boolean_bind(self):
        # Bind a Python bool into a BOOLEAN column and read it back (#54).
        self._setup_bool()
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, :b)", [True])
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (2, :b)", [False])
        self.conn.commit()
        self.cur.execute(f"SELECT id, flag FROM {self.TABLE} ORDER BY id")
        self.assertEqual(self.cur.fetchall(), [(1, True), (2, False)])


@unittest.skipUnless(_USER, _SKIP_REASON)
class VectorIntegration(_IntegrationBase):
    # Native VECTOR columns, 23ai+ (#55, TNS type 127). The server delivers the
    # vector as a LOB locator; pyoracle reads the binary image over TTI_LOBOPS
    # and decodes it to a list. Skipped on servers without the type.
    def _setup_vec(self, coltype):
        from oracle.exceptions import DatabaseError
        try:
            self.cur.execute(f"CREATE TABLE {self.TABLE} (v {coltype})")
        except DatabaseError as exc:
            # Pre-23ai: 21c rejects VECTOR with ORA-00902 (invalid datatype);
            # 11g's parser doesn't know the `VECTOR(n, type)` syntax at all and
            # raises ORA-00907 (missing right parenthesis). Skip on either.
            if exc.code in (902, 907):
                self.skipTest("native VECTOR type needs a 23ai+ server")
            raise

    def _roundtrip(self, coltype, literal):
        self._setup_vec(coltype)
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('{literal}')")
        self.conn.commit()
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        return self.cur.fetchone()[0]

    def _bind_roundtrip(self, coltype, value):
        # Bind a Python sequence (#55) and read it back.
        self._setup_vec(coltype)
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:v)", [value])
        self.conn.commit()
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        return self.cur.fetchone()[0]

    def test_float32(self):
        got = self._roundtrip("VECTOR(3, FLOAT32)", "[1.5, 2.5, 3.5]")
        self.assertEqual(got, [1.5, 2.5, 3.5])

    def test_float32_signed(self):
        got = self._roundtrip("VECTOR(4, FLOAT32)", "[-1, 0, 2.25, -8]")
        self.assertEqual(got, [-1.0, 0.0, 2.25, -8.0])

    def test_float64(self):
        got = self._roundtrip("VECTOR(3, FLOAT64)", "[1.5, 2.5, 3.5]")
        self.assertEqual(got, [1.5, 2.5, 3.5])

    def test_int8(self):
        got = self._roundtrip("VECTOR(4, INT8)", "[1, -2, 3, -4]")
        self.assertEqual(got, [1, -2, 3, -4])
        self.assertTrue(all(isinstance(v, int) for v in got))

    def test_binary(self):
        # BINARY (bit) vectors (#60): the literal gives one packed byte per 8
        # dimensions; pyoracle surfaces those packed bytes verbatim.
        got = self._roundtrip("VECTOR(16, BINARY)", "[170, 1]")
        self.assertEqual(got, [170, 1])
        self.assertTrue(all(isinstance(v, int) for v in got))

    # Binds (#62): pyoracle sends the native binary VECTOR image; covers plain
    # lists and typed array.array values.
    def test_bind_float32_list(self):
        self.assertEqual(
            self._bind_roundtrip("VECTOR(4, FLOAT32)", [-1, 0, 2.25, -8]),
            [-1.0, 0.0, 2.25, -8.0])

    def test_bind_float32_array(self):
        import array
        self.assertEqual(
            self._bind_roundtrip("VECTOR(3, FLOAT32)",
                                 array.array("f", [1.5, 2.5, 3.5])),
            [1.5, 2.5, 3.5])

    def test_bind_float64_array(self):
        import array
        self.assertEqual(
            self._bind_roundtrip("VECTOR(3, FLOAT64)",
                                 array.array("d", [0.1, 2.5, 3.5])),
            [0.1, 2.5, 3.5])

    def test_bind_int8(self):
        import array
        self.assertEqual(
            self._bind_roundtrip("VECTOR(4, INT8)",
                                 array.array("b", [1, -2, 3, -4])),
            [1, -2, 3, -4])

    def test_bind_binary(self):
        import array
        self.assertEqual(
            self._bind_roundtrip("VECTOR(16, BINARY)",
                                 array.array("B", [170, 1])),
            [170, 1])

    def test_sparse_roundtrip(self):
        # SPARSE vectors (#68): bind a SparseVector and read it back.
        from oracle.vector import SparseVector
        sv = SparseVector(8, [2, 5], [1.5, 2.5])
        self.assertEqual(
            self._bind_roundtrip("VECTOR(8, FLOAT32, SPARSE)", sv), sv)


@unittest.skipUnless(_USER, _SKIP_REASON)
class JSONIntegration(_IntegrationBase):
    # Native JSON (OSON) columns, 21c+ (#30). The server delivers the JSON
    # value as a LOB locator; pyoracle reads the OSON image over TTI_LOBOPS and
    # decodes it to a Python value. Skipped on servers without the JSON type.
    def _setup_json(self):
        from oracle.exceptions import DatabaseError
        try:
            self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER, doc JSON)")
        except DatabaseError as exc:
            if exc.code == 902:        # ORA-00902: invalid datatype (pre-21c)
                self.skipTest("native JSON type needs a 21c+ server")
            raise

    def _roundtrip(self, doc_text):
        # Single-row round trip: insert one JSON doc, read it back decoded.
        # (Multi-row JSON fetches ride the same LOB path as multi-row LOB reads
        # and share the #45 desync limitation, so keep it to one row here.)
        self.cur.execute(f"DELETE FROM {self.TABLE}")
        self.conn.commit()
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, JSON('{doc_text}'))")
        self.conn.commit()
        self.cur.execute(f"SELECT doc FROM {self.TABLE}")
        return self.cur.fetchone()[0]

    def test_object_array_scalars(self):
        self._setup_json()
        got = self._roundtrip('{"hello":"world","n":42,"arr":[1,2,3]}')
        self.assertEqual(got, {"hello": "world", "n": 42, "arr": [1, 2, 3]})

    def test_nested_with_bool_and_null(self):
        self._setup_json()
        got = self._roundtrip('{"a":{"b":[true,false,null],"s":"x"}}')
        self.assertEqual(got, {"a": {"b": [True, False, None], "s": "x"}})

    def test_top_level_array(self):
        self._setup_json()
        self.assertEqual(self._roundtrip('[1,2,3,"four",true]'),
                         [1, 2, 3, "four", True])

    def test_scalar_string(self):
        self._setup_json()
        self.assertEqual(self._roundtrip('"just a string"'), "just a string")

    def test_scalar_null(self):
        self._setup_json()
        self.assertIsNone(self._roundtrip('null'))

    def test_wide_object_over_255_keys(self):
        # > 255 distinct keys (#69): the OSON header uses a ub2 num_fnames and
        # the object node ub2 count + ub2 field-ids. A too-small offline fixture
        # can't reach this, so exercise it end-to-end.
        self._setup_json()
        doc = {f"key{i:03d}": i for i in range(300)}
        self.cur.execute(f"DELETE FROM {self.TABLE}")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, :doc)", [doc])
        self.conn.commit()
        self.cur.execute(f"SELECT doc FROM {self.TABLE}")
        got = self.cur.fetchone()[0]
        self.assertEqual(len(got), 300)
        self.assertEqual(got["key000"], 0)
        self.assertEqual(got["key299"], 299)

    # Binds (#50): a bare dict binds as JSON; oracle.JSON(value) forces JSON on
    # lists / scalars. pyoracle serialises to JSON text and the server casts it.
    def _bind_roundtrip(self, value):
        self.cur.execute(f"DELETE FROM {self.TABLE}")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (1, :doc)", [value])
        self.conn.commit()
        self.cur.execute(f"SELECT doc FROM {self.TABLE}")
        return self.cur.fetchone()[0]

    def test_bind_dict(self):
        self._setup_json()
        self.assertEqual(
            self._bind_roundtrip({"hello": "world", "n": 42, "arr": [1, 2, 3]}),
            {"hello": "world", "n": 42, "arr": [1, 2, 3]})

    def test_bind_nested_dict(self):
        self._setup_json()
        self.assertEqual(
            self._bind_roundtrip({"a": {"b": [True, False, None], "s": "x"}}),
            {"a": {"b": [True, False, None], "s": "x"}})

    def test_bind_json_wrapper_list(self):
        self._setup_json()
        self.assertEqual(
            self._bind_roundtrip(oracle.JSON([1, 2, 3, "four", True])),
            [1, 2, 3, "four", True])

    def test_bind_json_wrapper_scalar(self):
        self._setup_json()
        self.assertEqual(self._bind_roundtrip(oracle.JSON("just a string")),
                         "just a string")

    def test_bind_decimal_stays_exact(self):
        from decimal import Decimal
        self._setup_json()
        got = self._bind_roundtrip({"price": Decimal("19.99")})
        self.assertEqual(got, {"price": Decimal("19.99")})

    def test_large_documents_decode(self):
        # #88: reading a native JSON column whose OSON image uses the large-doc
        # encodings — string values >255 B (ub2 0x37), >64 KiB (ub4 0x38), a
        # tree >64 KiB (ub4 tree_size), and a container with >64 KiB of values /
        # >65535 entries (ub4 offsets / ub4 count). These bind via the text-cast
        # fallback (the compact encoder refuses them) and must round-trip on read.
        self._setup_json()
        cases = [
            {"s": "x" * 500},                              # ub2 string
            {"big": "y" * 70000},                          # ub4 string + ub4 tree
            list(range(30000)),                            # ub4 offsets (big tree)
            list(range(70000)),                            # ub4 count (>65535 elems)
            {"a": {"b": {"c": "z" * 1000}}, "l": ["s" * 400, "t" * 60000]},
        ]
        for n, v in enumerate(cases):
            wrapped = v if isinstance(v, dict) else oracle.JSON(v)
            got = self._bind_roundtrip(wrapped)
            self.assertEqual(got, v, f"case {n}")


@unittest.skipUnless(_USER, _SKIP_REASON)
class SodaIntegration(_IntegrationBase):
    # SODA collection management (#163 / #199), backed by DBMS_SODA. Needs an
    # Oracle 18c+ server; skipped below that.
    def setUp(self):
        super().setUp()
        if (self.conn.server_version >> 24) < 18:
            self.conn.close()
            self.skipTest("SODA needs an Oracle 18c+ server (DBMS_SODA)")
        self.soda = self.conn.getSodaDatabase()
        self._drop_all_collections()

    def _drop_all_collections(self):
        for n in self.soda.getCollectionNames():
            c = self.soda.openCollection(n)
            if c:
                c.drop()

    def tearDown(self):
        try:
            self._drop_all_collections()
        except Exception:
            # best-effort collection cleanup; tearDown still closes the conn
            pass
        super().tearDown()

    def test_create_open_list_drop(self):
        col = self.soda.createCollection("it_a")
        self.assertEqual(col.name, "it_a")
        self.assertIn("contentColumn", col.metadata)
        self.assertEqual(self.soda.openCollection("it_a").name, "it_a")
        self.assertIsNone(self.soda.openCollection("no_such_coll"))
        self.soda.createCollection("it_b")
        self.assertEqual(self.soda.getCollectionNames(), ["it_a", "it_b"])
        self.assertEqual(self.soda.getCollectionNames(limit=1), ["it_a"])
        self.assertEqual(self.soda.getCollectionNames("it_b"), ["it_b"])
        self.assertTrue(col.drop())        # dropped
        self.assertFalse(col.drop())       # already gone

    def test_truncate(self):
        col = self.soda.createCollection("it_trunc")
        # insert one document via DBMS_SODA directly (the document API is a later
        # #163 sub-ticket); truncate must then empty the collection.
        self.cur.execute(
            "DECLARE c SODA_COLLECTION_T; d SODA_DOCUMENT_T; n NUMBER; BEGIN "
            "c := DBMS_SODA.open_collection('it_trunc'); "
            "d := SODA_DOCUMENT_T(b_content => utl_raw.cast_to_raw('{\"a\":1}')); "
            "n := c.insert_one(d); END;")
        col.truncate()
        v = self.cur.var(oracle.NUMBER)
        self.cur.execute(
            "DECLARE c SODA_COLLECTION_T; BEGIN "
            "c := DBMS_SODA.open_collection('it_trunc'); "
            ":1 := c.find().count(); END;", [v])
        self.assertEqual(v.getvalue(), 0)

    def test_document_insert_and_read(self):
        col = self.soda.createCollection("it_docs")
        # insertOneAndGet returns server-assigned key / version / media type
        saved = col.insertOneAndGet(self.soda.createDocument({"name": "alice",
                                                              "age": 30}))
        self.assertTrue(saved.key)
        self.assertTrue(saved.version)
        self.assertEqual(saved.mediaType, "application/json")
        self.assertIsNone(saved.getContentAsBytes())     # no content returned

        # read it back by key -> content parsed as JSON
        got = col.find().key(saved.key).getOne()
        self.assertEqual(got.key, saved.key)
        content = got.getContent()
        self.assertEqual(content["name"], "alice")
        self.assertEqual(content["age"], 30)
        self.assertIsInstance(got.getContentAsString(), str)

        # insertOne accepts a bare value; a valid-but-absent key reads as None
        col.insertOne({"name": "bob"})
        self.assertIsNone(col.find().key("AABBCCDDEEFF00112233445566").getOne())

    def test_large_document_insert_and_read_guard(self):
        col = self.soda.createCollection("it_big")
        big = {"blob": "x" * 40000}              # > 32767-byte inline read limit
        saved = col.insertOneAndGet(big)         # insert is fine (temp LOB)
        self.assertTrue(saved.key)
        with self.assertRaises(oracle.NotSupportedError):
            col.find().key(saved.key).getOne()   # read guards against truncation

    def test_qbe_find(self):
        col = self.soda.createCollection("it_qbe")
        for age in (20, 25, 30, 35, 40):
            col.insertOne({"age": age})
        self.assertEqual(col.find().count(), 5)
        F = {"age": {"$gte": 30}}
        self.assertEqual(col.find().filter(F).count(), 3)
        ages = sorted(d.getContent()["age"]
                      for d in col.find().filter(F).getDocuments())
        self.assertEqual(ages, [30, 35, 40])
        # getOne with a filter; a repeated call must re-evaluate the filter
        # (regression: SODA's get_one() caches a bind filter, so getOne runs the
        # cursor path).
        self.assertEqual(
            col.find().filter({"age": 25}).getOne().getContent()["age"], 25)
        self.assertIsNone(col.find().filter({"age": 999}).getOne())
        self.assertEqual(len(col.find().limit(2).getDocuments()), 2)

    def test_getdocuments_overflow_guard(self):
        col = self.soda.createCollection("it_over")
        for i in range(5):
            col.insertOne({"i": i})
        import oracle.soda as _soda
        saved = _soda._DEFAULT_FETCH_CAP
        _soda._DEFAULT_FETCH_CAP = 2          # force overflow without a .limit()
        try:
            with self.assertRaises(oracle.NotSupportedError):
                col.find().getDocuments()
        finally:
            _soda._DEFAULT_FETCH_CAP = saved

    def test_update_delete_bulk(self):
        col = self.soda.createCollection("it_udb")
        # insertMany (one round trip)
        col.insertMany([{"n": 1}, {"n": 2}, {"n": 3}])
        self.assertEqual(col.find().count(), 3)
        saved = col.insertOneAndGet({"v": 1})

        # replaceOne by key (match + no match)
        self.assertTrue(col.find().key(saved.key).replaceOne({"v": 2}))
        self.assertEqual(col.find().key(saved.key).getOne().getContent()["v"], 2)
        self.assertFalse(
            col.find().key("AABBCCDDEEFF00112233445566").replaceOne({"v": 9}))

        # replaceOneAndGet -> new version; None when nothing matches
        got = col.find().key(saved.key).replaceOneAndGet({"v": 3})
        self.assertEqual(got.key, saved.key)
        self.assertTrue(got.version)
        self.assertIsNone(
            col.find().key("AABBCCDDEEFF00112233445566").replaceOneAndGet({}))

        # remove by filter -> count removed
        self.assertEqual(col.find().filter({"v": {"$exists": True}}).remove(), 1)
        self.assertEqual(col.find().count(), 3)
        # remove by key
        k = col.find().limit(1).getDocuments()[0].key
        self.assertEqual(col.find().key(k).remove(), 1)
        self.assertEqual(col.find().count(), 2)

    def test_indexing_and_data_guide(self):
        col = self.soda.createCollection("it_idx")
        for age in (20, 30, 40):
            col.insertOne({"name": "u", "age": age})
        # no data-guide index yet -> None (not an error)
        self.assertIsNone(col.getDataGuide())
        # functional index, dropped by name (present then absent)
        col.createIndex({"name": "IT_IDX_AGE",
                         "fields": [{"path": "age", "datatype": "number"}]})
        self.assertTrue(col.dropIndex("IT_IDX_AGE"))
        self.assertFalse(col.dropIndex("IT_IDX_AGE"))
        # data-guide search index -> getDataGuide returns the structure. The
        # JSON search indextype needs Oracle Text, which 21c XE lacks (ORA-29833),
        # so only assert the data guide where it can be built.
        try:
            col.createIndex({"name": "IT_SIDX", "dataguide": "on",
                             "search_on": "text_value"})
        except oracle.DatabaseError as exc:
            if getattr(exc, "code", None) == 29833:
                self.skipTest("JSON search index needs Oracle Text (absent on "
                              "21c XE)")
            raise
        dg = col.getDataGuide().getContent()
        self.assertEqual(dg["type"], "object")
        self.assertIn("age", dg["properties"])


@unittest.skipUnless(_USER, _SKIP_REASON)
class SqlDomainIntegration(_IntegrationBase):
    # 23ai SQL-domain columns (#53). At field version 17 a column with a SQL
    # domain carries its schema+name in the per-column describe; before the fix
    # that non-empty layout desynced the row decode. Needs a 23ai server AND the
    # CREATE DOMAIN privilege; skips otherwise (incl. pre-23ai, which lacks the
    # syntax). Run with PYORACLE_TEST_FIELD_VERSION=17 to exercise the fv17 path.
    DOMAIN = "PYO_DOM_T"

    def _setup_domain(self):
        from oracle.exceptions import DatabaseError
        try:
            self.cur.execute(f"DROP DOMAIN {self.DOMAIN} FORCE")
        except DatabaseError:
            # No leftover domain from a prior run (or pre-23ai, which has no
            # DROP DOMAIN) — nothing to clean up, proceed to create it.
            pass
        try:
            self.cur.execute(f"CREATE DOMAIN {self.DOMAIN} AS NUMBER(3,0)")
        except DatabaseError as exc:
            # pre-23ai doesn't know the DOMAIN syntax: 11g/21c raise ORA-00901
            # ("invalid CREATE command"), others 900/902/907; 1031 = the user
            # lacks CREATE DOMAIN. Skip on any of these.
            if exc.code in (900, 901, 902, 907, 1031):
                self.skipTest("SQL domains need a 23ai server + CREATE DOMAIN")
            raise

    def test_domain_column_select(self):
        self._setup_domain()
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} "
            f"(id NUMBER, d NUMBER DOMAIN {self.DOMAIN})")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (1, 42)")
        self.conn.commit()
        # A multi-column SELECT mixing the domain column would desync the row
        # decode before the fix; it should now return cleanly.
        self.cur.execute(f"SELECT id, d FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (1, 42))

    def tearDown(self):
        try:
            self.cur.execute(f"DROP DOMAIN {self.DOMAIN} FORCE")
        except Exception:
            # Best-effort teardown: the domain may never have been created
            # (skipped / pre-23ai test), so any drop error is irrelevant.
            pass
        super().tearDown()


@unittest.skipUnless(_USER, _SKIP_REASON)
class ChangePasswordIntegration(unittest.TestCase):
    """Connection.changepassword over the wire (#21). Each test changes the
    test user's password and always restores it (on the original, still-
    authenticated connection) so the rest of the suite is unaffected."""

    def _kwargs(self, password):
        return dict(host=_HOST, port=_PORT, user=_USER, password=password,
                    service_name=_SERVICE, autocommit=True, **_FV_KW)

    def setUp(self):
        # changepassword is gated on Oracle 9i (its O3LOGON password change
        # differs); skip the live tests there (#168).
        with oracle.connect(**self._kwargs(_PASSWORD)) as conn:
            if conn.field_version < FIELD_VERSION_10_2:
                self.skipTest("changepassword is not supported on Oracle 9i")

    def test_changepassword_roundtrip(self):
        new = _PASSWORD + "_chg9"
        with oracle.connect(**self._kwargs(_PASSWORD)) as conn:
            conn.changepassword(_PASSWORD, new)
            try:
                # The session that changed the password stays usable.
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM dual")
                self.assertEqual(cur.fetchone(), (1,))
                # The new password authenticates a fresh connection.
                with oracle.connect(**self._kwargs(new)) as v:
                    vc = v.cursor()
                    vc.execute("SELECT 1 FROM dual")
                    self.assertEqual(vc.fetchone(), (1,))
                # The old password no longer works.
                with self.assertRaises(oracle.DatabaseError):
                    oracle.connect(**self._kwargs(_PASSWORD)).close()
            finally:
                # Restore the original password on the still-authenticated
                # connection before the `with` closes it.
                conn.changepassword(new, _PASSWORD)
        # The original password is restored for the rest of the suite.
        with oracle.connect(**self._kwargs(_PASSWORD)):
            pass

    def test_changepassword_wrong_old_raises(self):
        # A wrong current password is rejected (ORA-28008) and changes nothing.
        with oracle.connect(**self._kwargs(_PASSWORD)) as conn:
            with self.assertRaises(oracle.DatabaseError):
                conn.changepassword("wrong_old_pw_xyz", "irrelevant9")
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM dual")
            self.assertEqual(cur.fetchone(), (1,))
        with oracle.connect(**self._kwargs(_PASSWORD)):
            pass


@unittest.skipUnless(_USER, _SKIP_REASON)
class RedirectIntegration(unittest.TestCase):
    """Follow a TNS_REDIRECT to reconnect to the address the server hands back
    (#23). A RedirectListener stands in for a shared-server / RAC listener: it
    answers the first CONNECT with a redirect to the real backend, and the
    driver must reconnect there and complete the handshake."""

    def test_sync_follows_redirect(self):
        with RedirectListener(_HOST, _PORT) as listener, \
                oracle.connect(
                    host=_HOST, port=listener.listen_port,
                    user=_USER, password=_PASSWORD, service_name=_SERVICE,
                    autocommit=True, **_FV_KW) as conn:
            # The connection ended up on the backend, not the listener.
            self.assertEqual(conn.port, _PORT)
            cur = conn.cursor()
            cur.execute("SELECT 'redirected' FROM dual")
            self.assertEqual(cur.fetchone(), ("redirected",))


@unittest.skipUnless(_USER, _SKIP_REASON)
class PoolIntegration(unittest.TestCase):
    """Verify the connection pool: pre-warm, acquire/release, capacity,
    and timeout behaviour."""

    def _kwargs(self, **extra):
        return dict(
            host=_HOST, port=_PORT,
            user=_USER, password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
            **extra,
        )

    def test_pre_warms_to_min_and_runs_query(self):
        Pool = oracle.create_pool(min=2, max=3, **self._kwargs())
        try:
            self.assertEqual(Pool.opened, 2)
            self.assertEqual(Pool.busy, 0)
            with Pool.acquire() as Conn:
                self.assertEqual(Pool.busy, 1)
                Cur = Conn.cursor()
                Cur.execute("SELECT 1 FROM dual")
                self.assertEqual(Cur.fetchone(), (1,))
            self.assertEqual(Pool.busy, 0)
        finally:
            Pool.close()

    def test_grows_to_max_and_releases_for_reuse(self):
        Pool = oracle.create_pool(min=1, max=3, **self._kwargs())
        try:
            G1 = Pool.acquire(); G1.__enter__()
            G2 = Pool.acquire(); G2.__enter__()
            G3 = Pool.acquire(); G3.__enter__()
            # All three checked out; pool can't grow further.
            self.assertEqual(Pool.busy, 3)
            self.assertEqual(Pool.opened, 3)
            G1.__exit__(None, None, None)
            self.assertEqual(Pool.busy, 2)
            # New acquire reuses, doesn't grow.
            with Pool.acquire() as _:
                self.assertEqual(Pool.busy, 3)
                self.assertEqual(Pool.opened, 3)
            G2.__exit__(None, None, None)
            G3.__exit__(None, None, None)
        finally:
            Pool.close()

    def test_acquire_times_out_when_full(self):
        Pool = oracle.create_pool(min=1, max=1, timeout=0.5, **self._kwargs())
        try:
            G = Pool.acquire(); G.__enter__()
            try:
                with self.assertRaises(oracle.InterfaceError):
                    Pool.acquire()
            finally:
                G.__exit__(None, None, None)
        finally:
            Pool.close()

    def test_acquire_after_close_raises(self):
        Pool = oracle.create_pool(min=1, max=2, **self._kwargs())
        Pool.close()
        with self.assertRaises(oracle.InterfaceError):
            Pool.acquire()

    def test_health_check_replaces_dead_connection(self):
        # idle_timeout=0 forces a health-check on every acquire. Kill
        # the underlying socket between release and acquire and verify
        # the pool transparently swaps in a fresh connection.
        Pool = oracle.create_pool(min=1, max=2, idle_timeout=0,
                                   **self._kwargs())
        try:
            G = Pool.acquire()
            Conn = G.__enter__()
            G.__exit__(None, None, None)
            # Sabotage the underlying socket.
            try:
                Conn.sock.close()
            except Exception:
                # Best-effort: deliberately sabotaging the socket for the
                # test; any close error here is irrelevant.
                pass
            # Next acquire must succeed (with a fresh connection,
            # ping caught the dead one).
            with Pool.acquire() as Conn2:
                Cur = Conn2.cursor()
                Cur.execute("SELECT 1 FROM dual")
                self.assertEqual(Cur.fetchone(), (1,))
        finally:
            Pool.close()


@unittest.skipUnless(_USER, _SKIP_REASON)
class RefBindIntegration(_IntegrationBase):
    # REF bind (#139): fetch a REF for a row object, bind it back into an INSERT
    # and into DEREF(?), and confirm it round-trips to the original object. REF
    # decode works on all tiers (#119), but the bind needs the 12c+ OAC — pre-12c
    # raises NotSupportedError, so the test skips there.
    TYPE = "PYORACLE_REF_PERSON"
    PEOPLE = "PYORACLE_REF_PEOPLE"
    REFS = "PYORACLE_REF_REFS"

    def _setup_schema(self):
        from oracle.exceptions import DatabaseError
        for s in (f"DROP TABLE {self.REFS}", f"DROP TABLE {self.PEOPLE}",
                  f"DROP TYPE {self.TYPE}"):
            try:
                self.cur.execute(s)
            except DatabaseError:
                # best-effort teardown of leftover objects
                pass
        self.cur.execute(
            f"CREATE TYPE {self.TYPE} AS OBJECT (id NUMBER, name VARCHAR2(40))")
        self.cur.execute(f"CREATE TABLE {self.PEOPLE} OF {self.TYPE}")
        self.cur.execute(f"INSERT INTO {self.PEOPLE} VALUES (1, 'Alice')")
        self.cur.execute(
            f"CREATE TABLE {self.REFS} (id NUMBER, r REF {self.TYPE})")

    def tearDown(self):
        try:
            cleanup = self.conn.cursor()
            for s in (f"DROP TABLE {self.REFS}", f"DROP TABLE {self.PEOPLE}",
                      f"DROP TYPE {self.TYPE}"):
                try:
                    cleanup.execute(s)
                except Exception:
                    # best-effort teardown of leftover objects
                    pass
            cleanup.close()
        finally:
            super().tearDown()

    def test_ref_bind_roundtrip(self):
        self._setup_schema()
        self.cur.execute(f"SELECT REF(p) FROM {self.PEOPLE} p WHERE p.id = 1")
        ref = self.cur.fetchone()[0]
        self.assertEqual(ref.type_name, self.TYPE)
        if getattr(self.conn, "field_version", 0) < FIELD_VERSION_12_1:
            self.skipTest("REF bind needs a 12.1+ server")
        # Bind into an INSERT, then DEREF the stored REF back to the object.
        self.cur.execute(
            f"INSERT INTO {self.REFS} (id, r) VALUES (:1, :2)", [100, ref])
        self.cur.execute(
            f"SELECT id, DEREF(r).name FROM {self.REFS} WHERE id = 100")
        self.assertEqual(self.cur.fetchone(), (100, "Alice"))
        # Bind into DEREF directly.
        self.cur.execute(f"SELECT DEREF(:1).name FROM dual", [ref])
        self.assertEqual(self.cur.fetchone(), ("Alice",))


@unittest.skipUnless(_USER, _SKIP_REASON)
class PipelineIntegration(_IntegrationBase):
    # Request pipelining (#132). Runs on every tier (serial execution); the
    # API, ordering and results match a single-round-trip pipelined run.
    def test_pipeline_runs_all_ops(self):
        self.cur.execute(
            f"CREATE TABLE {self.TABLE} (id NUMBER, name VARCHAR2(20))")
        p = oracle.create_pipeline()
        p.add_execute(f"INSERT INTO {self.TABLE} VALUES (1, 'a')")
        p.add_executemany(f"INSERT INTO {self.TABLE} VALUES (:1, :2)",
                          [(2, "b"), (3, "c")])
        p.add_commit()
        p.add_fetchall(f"SELECT id, name FROM {self.TABLE} ORDER BY id")
        p.add_fetchone(f"SELECT COUNT(*) FROM {self.TABLE}")
        results = self.conn.run_pipeline(p)
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r.error is None for r in results))
        self.assertEqual(results[3].rows, [(1, "a"), (2, "b"), (3, "c")])
        self.assertEqual(results[4].rows, [(3,)])

    def test_pipeline_continue_on_error(self):
        p = oracle.create_pipeline()
        p.add_execute("SELECT * FROM a_table_that_does_not_exist")
        p.add_fetchone("SELECT 42 FROM dual")
        results = self.conn.run_pipeline(p, continue_on_error=True)
        self.assertIsNotNone(results[0].error)
        self.assertEqual(results[1].rows, [(42,)])

    def test_pipeline_abort_raises(self):
        p = oracle.create_pipeline()
        p.add_execute("SELECT * FROM a_table_that_does_not_exist")
        p.add_fetchone("SELECT 42 FROM dual")
        with self.assertRaises(oracle.DatabaseError):
            self.conn.run_pipeline(p)


@unittest.skipUnless(_USER, _SKIP_REASON)
class SessionlessTransactionIntegration(unittest.TestCase):
    # Sessionless transactions (#133, 23ai). A transaction is started on one
    # session, suspended, then resumed and committed on a *different* session.
    # Needs two connections with autocommit off, so it manages its own
    # connections rather than the single-connection _IntegrationBase. Skips
    # below 23ai (begin raises NotSupportedError at field version < 23.1).
    TABLE = "PYORACLE_SL_TEST"

    def _conn(self):
        c = oracle.connect(host=_HOST, port=_PORT, user=_USER,
                           password=_PASSWORD, service_name=_SERVICE, **_FV_KW)
        c.autocommit = False
        return c

    def setUp(self):
        from oracle.exceptions import NotSupportedError
        self.conns = []
        setup = self._conn()
        self.conns.append(setup)
        cur = setup.cursor()
        try:
            cur.execute(f"DROP TABLE {self.TABLE}")
        except oracle.DatabaseError as e:
            if e.code != 942:
                raise
        cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        setup.commit()
        # Probe support up front so the whole class skips cleanly pre-23ai.
        try:
            setup.begin_sessionless_transaction("probe", timeout=10)
            setup.suspend_sessionless_transaction()
            setup.rollback()
        except NotSupportedError:
            self.skipTest("sessionless transactions need a 23ai+ server")

    def tearDown(self):
        for c in self.conns:
            try:
                c.close()
            except Exception:
                # best-effort close; the test already passed/failed
                pass

    def test_suspend_resume_commit_across_sessions(self):
        c1 = self._conn(); self.conns.append(c1)
        tid = c1.begin_sessionless_transaction("sl-it-1", timeout=120)
        self.assertEqual(tid, b"sl-it-1")
        c1.cursor().execute(f"INSERT INTO {self.TABLE} VALUES (10)")
        c1.suspend_sessionless_transaction()

        # An outsider must not see the uncommitted, suspended row.
        obs = self._conn(); self.conns.append(obs)
        ocur = obs.cursor()
        ocur.execute(f"SELECT COUNT(*) FROM {self.TABLE}")
        self.assertEqual(ocur.fetchone()[0], 0)

        c2 = self._conn(); self.conns.append(c2)
        c2.resume_sessionless_transaction("sl-it-1", timeout=120)
        c2.cursor().execute(f"INSERT INTO {self.TABLE} VALUES (20)")
        c2.commit()

        ocur.execute(f"SELECT id FROM {self.TABLE} ORDER BY id")
        self.assertEqual(ocur.fetchall(), [(10,), (20,)])

    def test_rollback_discards_sessionless_work(self):
        c = self._conn(); self.conns.append(c)
        c.begin_sessionless_transaction("sl-it-2", timeout=60)
        c.cursor().execute(f"INSERT INTO {self.TABLE} VALUES (99)")
        c.rollback()
        cur = c.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {self.TABLE}")
        self.assertEqual(cur.fetchone()[0], 0)

    def test_default_id_is_uuid_and_double_begin_rejected(self):
        c = self._conn(); self.conns.append(c)
        tid = c.begin_sessionless_transaction(timeout=30)
        self.assertEqual(len(tid), 16)              # uuid4 bytes
        with self.assertRaises(oracle.DatabaseError):
            c.begin_sessionless_transaction("other")  # already active
        c.suspend_sessionless_transaction()


_BFILE_TEST_FILE = "pyoracle_bfile_test.txt"
_BFILE_TEST_CONTENT = b"hello bfile from disk"


@unittest.skipUnless(_USER, _SKIP_REASON)
class AsyncConnectionIntegration(unittest.IsolatedAsyncioTestCase):
    """Verify the async surface: connect_async, AsyncCursor, fetch
    flow, async iteration, context managers."""

    def _kwargs(self):
        return dict(
            host=_HOST, port=_PORT,
            user=_USER, password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
        )

    async def asyncSetUp(self):
        # Skip the async tests whose feature Oracle 9i (fv2) lacks, mirroring
        # _IntegrationBase._skip_if_fv2_unsupported for this standalone async
        # class (#168). A quick connect just to learn the negotiated field
        # version, then close — the tests open their own connections.
        Reason = _fv2_skip_reason(self._testMethodName)
        if Reason is None:
            return
        Conn = await oracle.connect_async(**self._kwargs())
        Fv = Conn.field_version
        await Conn.close()
        if Fv < FIELD_VERSION_10_2:
            self.skipTest(Reason)

    async def test_connect_and_simple_query(self):
        Conn = await oracle.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute("SELECT 1 FROM dual")
            self.assertEqual(await Cur.fetchone(), (1,))
            await Cur.close()
        finally:
            await Conn.close()

    async def test_follows_redirect(self):
        # Async mirror of RedirectIntegration: follow a TNS_REDIRECT to the
        # backend the listener hands back (#23).
        with RedirectListener(_HOST, _PORT) as listener:
            Kw = self._kwargs()
            Kw["port"] = listener.listen_port
            Conn = await oracle.connect_async(**Kw)
            try:
                self.assertEqual(Conn.port, _PORT)
                Cur = Conn.cursor()
                await Cur.execute("SELECT 'redirected' FROM dual")
                self.assertEqual(await Cur.fetchone(), ("redirected",))
            finally:
                await Conn.close()

    async def test_context_managers(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute("SELECT 'hi' FROM dual")
                self.assertEqual(await Cur.fetchone(), ("hi",))

    async def test_async_iteration_yields_all_rows(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT LEVEL FROM dual CONNECT BY LEVEL <= 5"
                )
                Rows = [row async for row in Cur]
                self.assertEqual(Rows, [(1,), (2,), (3,), (4,), (5,)])

    async def test_fetchall_and_fetchmany(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT LEVEL FROM dual CONNECT BY LEVEL <= 4"
                )
                # fetchmany(2) → first batch
                First = await Cur.fetchmany(2)
                self.assertEqual(First, [(1,), (2,)])
                # fetchall() → remainder
                Rest = await Cur.fetchall()
                self.assertEqual(Rest, [(3,), (4,)])

    async def test_named_bind(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT :v FROM dual", {"v": 42}
                )
                self.assertEqual(await Cur.fetchone(), (42,))

    async def test_ddl_dml_roundtrip(self):
        # DDL → DML → SELECT round-trip using a scratch table.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                try:
                    await Cur.execute("DROP TABLE PYORACLE_ASYNC_TEST")
                except oracle.DatabaseError as e:
                    if e.code != 942:
                        raise
                await Cur.execute(
                    "CREATE TABLE PYORACLE_ASYNC_TEST (id NUMBER, v VARCHAR2(10))"
                )
                for n in range(3):
                    await Cur.execute(
                        "INSERT INTO PYORACLE_ASYNC_TEST VALUES (:id, :v)",
                        {"id": n, "v": f"r{n}"},
                    )
                await Cur.execute(
                    "SELECT id, v FROM PYORACLE_ASYNC_TEST ORDER BY id"
                )
                self.assertEqual(
                    await Cur.fetchall(),
                    [(0, "r0"), (1, "r1"), (2, "r2")],
                )
                await Cur.execute("DROP TABLE PYORACLE_ASYNC_TEST")

    async def test_vector_bind_roundtrip(self):
        # Async parity for VECTOR binds (#55): bind a sequence, read it back.
        import array
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, "PYORACLE_ASYNC_VEC")
                try:
                    await Cur.execute(
                        "CREATE TABLE PYORACLE_ASYNC_VEC (v VECTOR(3, FLOAT32))")
                except oracle.DatabaseError as e:
                    if e.code in (902, 907):
                        self.skipTest("native VECTOR type needs a 23ai+ server")
                    raise
                await Cur.execute(
                    "INSERT INTO PYORACLE_ASYNC_VEC VALUES (:v)",
                    [array.array("f", [1.5, 2.5, 3.5])])
                await Cur.execute("SELECT v FROM PYORACLE_ASYNC_VEC")
                self.assertEqual(await Cur.fetchone(), ([1.5, 2.5, 3.5],))
                await self._drop_async(Cur, "PYORACLE_ASYNC_VEC")

    async def test_sparse_vector_bind_roundtrip(self):
        # Async parity for SPARSE vectors (#68).
        from oracle.vector import SparseVector
        sv = SparseVector(8, [2, 5], [1.5, 2.5])
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, "PYORACLE_ASYNC_SPV")
                try:
                    await Cur.execute(
                        "CREATE TABLE PYORACLE_ASYNC_SPV "
                        "(v VECTOR(8, FLOAT32, SPARSE))")
                except oracle.DatabaseError as e:
                    if e.code in (902, 907):
                        self.skipTest("native VECTOR type needs a 23ai+ server")
                    raise
                await Cur.execute(
                    "INSERT INTO PYORACLE_ASYNC_SPV VALUES (:v)", [sv])
                await Cur.execute("SELECT v FROM PYORACLE_ASYNC_SPV")
                self.assertEqual(await Cur.fetchone(), (sv,))
                await self._drop_async(Cur, "PYORACLE_ASYNC_SPV")

    async def test_json_bind_roundtrip(self):
        # Async parity for JSON binds (#50): bind a dict, read it back.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, "PYORACLE_ASYNC_JSON")
                try:
                    await Cur.execute(
                        "CREATE TABLE PYORACLE_ASYNC_JSON (doc JSON)")
                except oracle.DatabaseError as e:
                    if e.code == 902:
                        self.skipTest("native JSON type needs a 21c+ server")
                    raise
                await Cur.execute(
                    "INSERT INTO PYORACLE_ASYNC_JSON VALUES (:doc)",
                    [{"k": "v", "n": [1, 2, 3]}])
                await Cur.execute("SELECT doc FROM PYORACLE_ASYNC_JSON")
                self.assertEqual(await Cur.fetchone(),
                                 ({"k": "v", "n": [1, 2, 3]},))
                await self._drop_async(Cur, "PYORACLE_ASYNC_JSON")

    async def _drop_async(self, cur, table):
        try:
            await cur.execute(f"DROP TABLE {table}")
        except oracle.DatabaseError as e:
            if e.code != 942:
                raise

    async def test_ping_succeeds(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            # Ping completes cleanly on a freshly-authenticated session;
            # the test just verifies no exception escapes.
            await Conn.ping()

    async def test_changepassword_roundtrip(self):
        # Async mirror of ChangePasswordIntegration (#21): change the test
        # user's password and always restore it on the original session.
        new = _PASSWORD + "_achg9"
        Kw = self._kwargs()
        Conn = await oracle.connect_async(**dict(Kw, password=_PASSWORD))
        try:
            await Conn.changepassword(_PASSWORD, new)
            try:
                Cur = Conn.cursor()
                await Cur.execute("SELECT 1 FROM dual")
                self.assertEqual(await Cur.fetchone(), (1,))
                V = await oracle.connect_async(**dict(Kw, password=new))
                await V.close()
                with self.assertRaises(oracle.DatabaseError):
                    Bad = await oracle.connect_async(
                        **dict(Kw, password=_PASSWORD))
                    await Bad.close()
            finally:
                await Conn.changepassword(new, _PASSWORD)
        finally:
            await Conn.close()
        Ok = await oracle.connect_async(**dict(Kw, password=_PASSWORD))
        await Ok.close()

    async def test_changepassword_wrong_old_raises(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            with self.assertRaises(oracle.DatabaseError):
                await Conn.changepassword("wrong_old_pw_xyz", "irrelevant9")
            Cur = Conn.cursor()
            await Cur.execute("SELECT 1 FROM dual")
            self.assertEqual(await Cur.fetchone(), (1,))

    async def test_commit_persists_dml(self):
        # autocommit=False, then explicit commit. A second connection
        # sees the row.
        Kw = self._kwargs()
        Kw["autocommit"] = False
        async with await oracle.connect_async(**Kw) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, "PYORACLE_ASYNC_TX")
                # CREATE TABLE auto-commits server-side regardless of the
                # client flag, so we issue it first and then test commit /
                # rollback against the rows.
                await Cur.execute(
                    "CREATE TABLE PYORACLE_ASYNC_TX (id NUMBER)"
                )
                await Cur.execute("INSERT INTO PYORACLE_ASYNC_TX VALUES (1)")
                await Conn.commit()
        async with await oracle.connect_async(**Kw) as Conn2:
            async with Conn2.cursor() as Cur:
                await Cur.execute("SELECT id FROM PYORACLE_ASYNC_TX")
                self.assertEqual(await Cur.fetchall(), [(1,)])
                await Cur.execute("DROP TABLE PYORACLE_ASYNC_TX")

    async def test_rollback_discards_dml(self):
        Kw = self._kwargs()
        Kw["autocommit"] = False
        async with await oracle.connect_async(**Kw) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, "PYORACLE_ASYNC_RB")
                await Cur.execute(
                    "CREATE TABLE PYORACLE_ASYNC_RB (id NUMBER)"
                )
                await Cur.execute("INSERT INTO PYORACLE_ASYNC_RB VALUES (1)")
                await Cur.execute("INSERT INTO PYORACLE_ASYNC_RB VALUES (2)")
                await Conn.rollback()
                # After rollback, the table exists (DDL auto-committed)
                # but the rows are gone.
                await Cur.execute("SELECT COUNT(*) FROM PYORACLE_ASYNC_RB")
                self.assertEqual(await Cur.fetchone(), (0,))
                await Cur.execute("DROP TABLE PYORACLE_ASYNC_RB")

    async def test_lob_auto_resolve(self):
        # CLOB / BLOB / NULL / EMPTY all surface as Python str/bytes/None
        # through the auto-resolve in `AsyncCursor.execute`.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, "PYORACLE_ASYNC_LOB")
                await Cur.execute(
                    "CREATE TABLE PYORACLE_ASYNC_LOB (id NUMBER, c CLOB, b BLOB)"
                )
                await Cur.execute(
                    "INSERT INTO PYORACLE_ASYNC_LOB VALUES (1, NULL, NULL)"
                )
                await Cur.execute(
                    "INSERT INTO PYORACLE_ASYNC_LOB VALUES "
                    "(2, EMPTY_CLOB(), EMPTY_BLOB())"
                )
                await Cur.execute(
                    "INSERT INTO PYORACLE_ASYNC_LOB VALUES "
                    "(3, 'hello async clob', HEXTORAW('DEADBEEF'))"
                )
                await Cur.execute(
                    "SELECT id, c, b FROM PYORACLE_ASYNC_LOB ORDER BY id"
                )
                Rows = await Cur.fetchall()
                self.assertEqual(Rows, [
                    (1, None, None),
                    (2, "", b""),
                    (3, "hello async clob", b"\xde\xad\xbe\xef"),
                ])
                await Cur.execute("DROP TABLE PYORACLE_ASYNC_LOB")

    async def test_error_then_large_lob_stays_synced(self):
        # #45 (async parity): errored calls leave break/reset markers; a few of
        # them followed by a large CLOB read must not desync the stream.
        from oracle.exceptions import DatabaseError
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                self.skipTest(
                    "Oracle 9i has no streamed LOB/LONG bind path (#169)")
            async with Conn.cursor() as Cur:
                await self._drop_async(Cur, "PYORACLE_ASYNC_LOB45")
                await Cur.execute(
                    "CREATE TABLE PYORACLE_ASYNC_LOB45 (id NUMBER, c CLOB)")
                Big = "A" * 50000
                await Cur.execute(
                    "INSERT INTO PYORACLE_ASYNC_LOB45 VALUES (1, :c)",
                    {"c": Big})
                await Conn.commit()
                for _ in range(8):
                    with self.assertRaises(DatabaseError):
                        await Cur.execute(
                            "SELECT * FROM pyoracle_no_such_table_45")
                        await Cur.fetchall()
                    await Cur.execute(
                        "SELECT c FROM PYORACLE_ASYNC_LOB45 WHERE id=1")
                    (Got,) = await Cur.fetchone()
                    self.assertEqual(len(Got), len(Big))
                    self.assertEqual(Got, Big)
                await Cur.execute("DROP TABLE PYORACLE_ASYNC_LOB45")

    async def test_async_plsql_in_bind(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute("CREATE TABLE PYORACLE_ASYNC_PLSQL (v NUMBER)")
                try:
                    await Cur.execute(
                        "BEGIN INSERT INTO PYORACLE_ASYNC_PLSQL "
                        "VALUES (:x); END;", [42])
                    await Cur.execute("SELECT v FROM PYORACLE_ASYNC_PLSQL")
                    self.assertEqual(await Cur.fetchone(), (42,))
                finally:
                    await Cur.execute("DROP TABLE PYORACLE_ASYNC_PLSQL")

    async def test_async_callproc_out_and_inout(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "CREATE OR REPLACE PROCEDURE PYORACLE_ASYNC_PROC"
                    "(p_in IN NUMBER, p_out OUT NUMBER, p_io IN OUT VARCHAR2) AS "
                    "BEGIN p_out := p_in * 2; p_io := p_io || '!'; END;")
                try:
                    o = Cur.var(oracle.NUMBER)
                    io = Cur.var(oracle.STRING)
                    io.setvalue(0, "hi")
                    ret = await Cur.callproc("PYORACLE_ASYNC_PROC", [5, o, io])
                    self.assertEqual(ret, [5, 10, "hi!"])
                    self.assertEqual(o.getvalue(), 10)
                    self.assertEqual(io.getvalue(), "hi!")
                finally:
                    await Cur.execute("DROP PROCEDURE PYORACLE_ASYNC_PROC")

    async def test_async_execute_out_var(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                y = Cur.var(oracle.NUMBER)
                await Cur.execute("BEGIN :y := 7 * 6; END;", [y])
                self.assertEqual(y.getvalue(), 42)

    async def test_async_out_extended_types(self):
        # OUT binds for the extended scalar types (issue #17), async path.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                self.skipTest(
                    "BINARY_DOUBLE / INTERVAL are 10g+ types; Oracle 9i lacks them")
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "CREATE OR REPLACE PROCEDURE PYORACLE_ASYNC_OUTX"
                    "(o_ts OUT TIMESTAMP, o_bd OUT BINARY_DOUBLE, "
                    " o_ids OUT INTERVAL DAY TO SECOND, "
                    " o_iym OUT INTERVAL YEAR TO MONTH) AS BEGIN "
                    "o_ts := TIMESTAMP '2026-06-07 13:14:15.5'; "
                    "o_bd := 2.25; "
                    "o_ids := INTERVAL '1 02:03:04.5' DAY TO SECOND; "
                    "o_iym := INTERVAL '3-7' YEAR TO MONTH; END;")
                try:
                    ts = Cur.var(oracle.DB_TYPE_TIMESTAMP)
                    bd = Cur.var(oracle.DB_TYPE_BINARY_DOUBLE)
                    ids = Cur.var(oracle.DB_TYPE_INTERVAL_DS)
                    iym = Cur.var(oracle.DB_TYPE_INTERVAL_YM)
                    await Cur.callproc("PYORACLE_ASYNC_OUTX", [ts, bd, ids, iym])
                    self.assertEqual(
                        ts.getvalue(),
                        datetime.datetime(2026, 6, 7, 13, 14, 15, 500000))
                    self.assertEqual(bd.getvalue(), 2.25)
                    self.assertEqual(
                        ids.getvalue(),
                        datetime.timedelta(days=1, hours=2, minutes=3,
                                           seconds=4, milliseconds=500))
                    self.assertEqual(iym.getvalue(), oracle.IntervalYM(3, 7))
                finally:
                    await Cur.execute("DROP PROCEDURE PYORACLE_ASYNC_OUTX")

    async def test_async_scroll(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            # Scrollable cursor (#161) on the async path.
            async with Conn.cursor(scrollable=True) as Cur:
                self.assertIs(Cur.scrollable, True)
                await Cur.execute("CREATE TABLE PYORACLE_ASYNC_SCROLL (id NUMBER)")
                try:
                    # Single inserts (not executemany) so scrollable cursors —
                    # which are buffer-backed and work on every tier — can also
                    # be exercised on 9i (#161).
                    for i in range(1, 11):
                        await Cur.execute(
                            "INSERT INTO PYORACLE_ASYNC_SCROLL VALUES (:1)", [i])
                    Conn.fetch = 4
                    await Cur.execute(
                        "SELECT id FROM PYORACLE_ASYNC_SCROLL ORDER BY id")
                    await Cur.scroll(mode="last")
                    self.assertEqual(await Cur.fetchone(), (10,))
                    await Cur.scroll(3, mode="absolute")
                    self.assertEqual(await Cur.fetchone(), (3,))
                    await Cur.scroll(mode="first")
                    self.assertEqual(await Cur.fetchone(), (1,))
                    with self.assertRaises(IndexError):
                        await Cur.scroll(-1, mode="relative")
                finally:
                    await Cur.execute("DROP TABLE PYORACLE_ASYNC_SCROLL")

    async def test_async_scrollable_lazy(self):
        # Server-side lazy scrollable cursor on the async path (#181), 10g+:
        # fetch-on-demand across batches + scroll modes + the LAST-after-EOF
        # duplicate-value (bit-vector reuse) case.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                self.skipTest("server-side scroll needs 10g+")
            async with Conn.cursor(scrollable=True) as Cur:
                Cur.prefetchrows = 2
                Cur.arraysize = 3
                await Cur.execute("CREATE TABLE PYORACLE_ASYNC_LAZY (id NUMBER)")
                try:
                    for i in range(1, 9):
                        await Cur.execute(
                            "INSERT INTO PYORACLE_ASYNC_LAZY VALUES (:1)", [i])
                    await Cur.execute(
                        "SELECT id FROM PYORACLE_ASYNC_LAZY ORDER BY id")
                    self.assertTrue(Cur._scroll_active)
                    got = [r[0] for r in await Cur.fetchmany(5)]   # crosses batches
                    self.assertEqual(got, [1, 2, 3, 4, 5])
                    await Cur.scroll(6, mode="absolute")
                    self.assertEqual((await Cur.fetchone())[0], 6)
                    # LAST-after-EOF duplicate value via a big arraysize.
                    Cur.arraysize = 50
                    await Cur.scroll(mode="first")
                    self.assertEqual([r[0] for r in await Cur.fetchall()],
                                     list(range(1, 9)))
                    await Cur.scroll(mode="last")
                    self.assertEqual((await Cur.fetchone())[0], 8)
                finally:
                    await Cur.execute("DROP TABLE PYORACLE_ASYNC_LAZY")

    async def test_async_fetch_df(self):
        # Arrow / DataFrame bulk fetch (#162) on the async path.
        import pyarrow as pa
        table = "PYORACLE_ASYNC_DF"
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(f"CREATE TABLE {table} (id NUMBER)")
                try:
                    for i in range(1, 8):
                        await Cur.execute(
                            f"INSERT INTO {table} VALUES (:1)", [i])
                    await Cur.execute(f"SELECT id FROM {table} ORDER BY id")
                    t = await Cur.fetch_df_all()
                    self.assertIsInstance(t, pa.Table)
                    self.assertEqual(t.column("ID").to_pylist(), list(range(1, 8)))
                    await Cur.execute(f"SELECT id FROM {table} ORDER BY id")
                    sizes = [b.num_rows async for b in Cur.fetch_df_batches(size=3)]
                    self.assertEqual(sizes, [3, 3, 1])
                finally:
                    await Cur.execute(f"DROP TABLE {table}")

    async def test_async_soda_collections(self):
        # SODA collection management (#163 / #199) on the async path; 18c+ only.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            if (Conn.server_version >> 24) < 18:
                self.skipTest("SODA needs an Oracle 18c+ server (DBMS_SODA)")
            soda = Conn.getSodaDatabase()
            for n in await soda.getCollectionNames():
                c = await soda.openCollection(n)
                if c:
                    await c.drop()
            col = await soda.createCollection("it_async")
            self.assertEqual(col.name, "it_async")
            self.assertIn("contentColumn", await col.get_metadata())
            self.assertEqual(await soda.getCollectionNames(), ["it_async"])
            self.assertIsNone(await soda.openCollection("no_such_coll"))
            # document insert + read by key on the async path (#200)
            saved = await col.insertOneAndGet(soda.createDocument({"x": 1}))
            self.assertTrue(saved.key)
            got = await col.find().key(saved.key).getOne()
            self.assertEqual(got.getContent()["x"], 1)
            self.assertIsNone(
                await col.find().key("AABBCCDDEEFF00112233445566").getOne())
            # QBE on the async path (#201)
            await col.insertOne({"x": 2})
            self.assertEqual(await col.find().filter({"x": {"$gte": 1}}).count(), 2)
            docs = await col.find().filter({"x": 2}).getDocuments()
            self.assertEqual([d.getContent()["x"] for d in docs], [2])
            self.assertIsNone(await col.find().filter({"x": 999}).getOne())
            # update / delete / bulk on the async path (#202)
            await col.insertMany([{"x": 3}, {"x": 4}])
            self.assertTrue(await col.find().key(saved.key).replaceOne({"x": 5}))
            g = await col.find().key(saved.key).replaceOneAndGet({"x": 6})
            self.assertEqual(g.key, saved.key)
            self.assertEqual(await col.find().key(saved.key).remove(), 1)
            # indexing + data guide on the async path (#203)
            self.assertIsNone(await col.getDataGuide())
            await col.createIndex({"name": "AIDX",
                                   "fields": [{"path": "x", "datatype": "number"}]})
            self.assertTrue(await col.dropIndex("AIDX"))
            self.assertTrue(await col.drop())
            self.assertFalse(await col.drop())

    async def test_async_end_to_end_tracing(self):
        # End-to-end tracing (#183) on the async path; 12c+ only.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_12_1:
                with self.assertRaises(oracle.NotSupportedError):
                    Conn.module = "M"
                return
            Conn.module = "AMOD"
            Conn.action = "AACT"
            Conn.client_identifier = "ACLID"
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT SYS_CONTEXT('USERENV','MODULE'), "
                    "SYS_CONTEXT('USERENV','ACTION'), "
                    "SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') FROM dual")
                self.assertEqual(await Cur.fetchone(), ("AMOD", "AACT", "ACLID"))

    async def test_async_repeated_execute_no_cursor_leak(self):
        # #191 on the async path.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_10_2:
                return
            Cur = Conn.cursor()
            try:
                await Cur.execute("DROP TABLE PYO_LEAK191A")
            except oracle.DatabaseError:
                # best-effort drop of a table that may not exist
                pass
            await Cur.execute("CREATE TABLE PYO_LEAK191A (id NUMBER)")
            try:
                for i in range(400):
                    await Cur.execute("INSERT INTO PYO_LEAK191A VALUES (:1)", [i])
                await Conn.commit()
                await Cur.execute("SELECT COUNT(*) FROM PYO_LEAK191A")
                self.assertEqual((await Cur.fetchone())[0], 400)
            finally:
                await Cur.execute("DROP TABLE PYO_LEAK191A")

    async def test_async_executemany(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute("CREATE TABLE PYORACLE_ASYNC_EM (id NUMBER)")
                try:
                    await Cur.executemany(
                        "INSERT INTO PYORACLE_ASYNC_EM VALUES (:1)",
                        [(i,) for i in range(8)])
                    self.assertEqual(Cur.rowcount, 8)
                    await Cur.execute("SELECT COUNT(*) FROM PYORACLE_ASYNC_EM")
                    self.assertEqual(await Cur.fetchone(), (8,))
                finally:
                    await Cur.execute("DROP TABLE PYORACLE_ASYNC_EM")

    async def test_async_executemany_batcherrors(self):
        # Async mirror of test_executemany_batcherrors (#18): per-row constraint
        # violations are collected, not raised, and the good rows still apply.
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute("CREATE TABLE PYORACLE_ASYNC_BE "
                                  "(id NUMBER PRIMARY KEY, v VARCHAR2(10))")
                try:
                    await Cur.executemany(
                        "INSERT INTO PYORACLE_ASYNC_BE VALUES (:1, :2)",
                        [(1, "a"), (2, "b"), (1, "dup"), (3, "c"), (2, "d2")],
                        batcherrors=True)
                    errs = Cur.getbatcherrors()
                    self.assertEqual([(e.offset, e.code) for e in errs],
                                     [(2, 1), (4, 1)])
                    await Cur.execute(
                        "SELECT id FROM PYORACLE_ASYNC_BE ORDER BY id")
                    self.assertEqual([r[0] for r in await Cur.fetchall()],
                                     [1, 2, 3])
                finally:
                    await Cur.execute("DROP TABLE PYORACLE_ASYNC_BE")

    async def test_async_executemany_arraydmlrowcounts(self):
        # Async mirror of test_executemany_arraydmlrowcounts_update (#18).
        from oracle.tns import FIELD_VERSION_12_1
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version < FIELD_VERSION_12_1:
                self.skipTest("arraydmlrowcounts needs a 12.1+ server")
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "CREATE TABLE PYORACLE_ASYNC_ADR (g NUMBER, v NUMBER)")
                try:
                    await Cur.executemany(
                        "INSERT INTO PYORACLE_ASYNC_ADR VALUES (:1, :2)",
                        [(1, 1), (1, 2), (2, 3), (1, 4), (3, 5), (3, 6)])
                    await Cur.executemany(
                        "UPDATE PYORACLE_ASYNC_ADR SET v = v + 10 WHERE g = :1",
                        [(1,), (2,), (3,), (9,)], arraydmlrowcounts=True)
                    self.assertEqual(Cur.getarraydmlrowcounts(), [3, 1, 2, 0])
                    # Combined with batcherrors a failed iteration counts 0.
                    await Cur.executemany(
                        "INSERT INTO PYORACLE_ASYNC_ADR VALUES (:1, :2)",
                        [(7, 7), (7, 7)])
                    await Cur.executemany(
                        "INSERT INTO PYORACLE_ASYNC_ADR VALUES (:1, :2)",
                        [(8, 8), (9, 9)], arraydmlrowcounts=True)
                    self.assertEqual(Cur.getarraydmlrowcounts(), [1, 1])
                finally:
                    await Cur.execute("DROP TABLE PYORACLE_ASYNC_ADR")

    async def test_async_arraydmlrowcounts_unsupported_on_11g(self):
        # On an 11g server the async feature is rejected up front, same as sync.
        from oracle.tns import FIELD_VERSION_12_1
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            if Conn.field_version >= FIELD_VERSION_12_1:
                self.skipTest("server supports arraydmlrowcounts")
            async with Conn.cursor() as Cur:
                await Cur.execute("CREATE TABLE PYORACLE_ASYNC_NS (id NUMBER)")
                try:
                    with self.assertRaises(oracle.NotSupportedError):
                        await Cur.executemany(
                            "INSERT INTO PYORACLE_ASYNC_NS VALUES (:1)",
                            [(1,), (2,)], arraydmlrowcounts=True)
                finally:
                    await Cur.execute("DROP TABLE PYORACLE_ASYNC_NS")

    async def test_async_callproc_refcursor(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "CREATE OR REPLACE PROCEDURE PYORACLE_ASYNC_RC"
                    "(p_rc OUT SYS_REFCURSOR) AS BEGIN OPEN p_rc FOR "
                    "SELECT 1 AS a, 'x' AS b FROM dual "
                    "UNION ALL SELECT 2, 'y' FROM dual; END;")
                try:
                    rc = Cur.var(oracle.CURSOR)
                    await Cur.callproc("PYORACLE_ASYNC_RC", [rc])
                    nested = rc.getvalue()
                    self.assertEqual([d[0] for d in nested.description],
                                     ["A", "B"])
                    self.assertEqual(await nested.fetchall(),
                                     [(1, "x"), (2, "y")])
                finally:
                    await Cur.execute("DROP PROCEDURE PYORACLE_ASYNC_RC")

    async def test_async_callfunc(self):
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "CREATE OR REPLACE FUNCTION PYORACLE_ASYNC_FUNC"
                    "(p IN NUMBER) RETURN NUMBER AS BEGIN RETURN p * 2; END;")
                try:
                    self.assertEqual(
                        await Cur.callfunc("PYORACLE_ASYNC_FUNC",
                                           oracle.NUMBER, [21]), 42)
                finally:
                    await Cur.execute("DROP FUNCTION PYORACLE_ASYNC_FUNC")

    async def test_async_pipeline(self):
        # Async mirror of PipelineIntegration (#132).
        table = "PYORACLE_APIPE"
        async with await oracle.connect_async(**self._kwargs()) as Conn:
            cur = Conn.cursor()
            try:
                await cur.execute(f"DROP TABLE {table}")
            except oracle.DatabaseError:
                # best-effort drop of a table that may not exist
                pass
            await cur.execute(f"CREATE TABLE {table} (id NUMBER)")
            p = oracle.create_pipeline()
            p.add_execute(f"INSERT INTO {table} VALUES (1)")
            p.add_executemany(f"INSERT INTO {table} VALUES (:1)", [(2,), (3,)])
            p.add_commit()
            p.add_fetchall(f"SELECT id FROM {table} ORDER BY id")
            results = await Conn.run_pipeline(p)
            self.assertEqual(results[3].rows, [(1,), (2,), (3,)])
            self.assertTrue(all(r.error is None for r in results))
            await cur.execute(f"DROP TABLE {table}")

    async def test_async_ref_bind(self):
        # Async mirror of RefBindIntegration (#139): fetch a REF, bind it back.
        from oracle.tns_consts import FIELD_VERSION_12_1 as _FV12
        TYPE, PEOPLE, REFS = ("PYORACLE_AREF_T", "PYORACLE_AREF_PEOPLE",
                              "PYORACLE_AREF_REFS")
        Conn = await oracle.connect_async(**self._kwargs())
        try:
            cur = Conn.cursor()
            for s in (f"DROP TABLE {REFS}", f"DROP TABLE {PEOPLE}",
                      f"DROP TYPE {TYPE}"):
                try:
                    await cur.execute(s)
                except oracle.DatabaseError:
                    # best-effort drop of a table that may not exist
                    pass
            await cur.execute(
                f"CREATE TYPE {TYPE} AS OBJECT (id NUMBER, name VARCHAR2(40))")
            await cur.execute(f"CREATE TABLE {PEOPLE} OF {TYPE}")
            await cur.execute(f"INSERT INTO {PEOPLE} VALUES (1, 'Alice')")
            await cur.execute(f"CREATE TABLE {REFS} (id NUMBER, r REF {TYPE})")
            await cur.execute(f"SELECT REF(p) FROM {PEOPLE} p WHERE p.id = 1")
            ref = (await cur.fetchone())[0]
            if getattr(Conn, "field_version", 0) < _FV12:
                self.skipTest("REF bind needs a 12.1+ server")
            await cur.execute(
                f"INSERT INTO {REFS} (id, r) VALUES (:1, :2)", [100, ref])
            await cur.execute(
                f"SELECT id, DEREF(r).name FROM {REFS} WHERE id = 100")
            self.assertEqual(await cur.fetchone(), (100, "Alice"))
            for s in (f"DROP TABLE {REFS}", f"DROP TABLE {PEOPLE}",
                      f"DROP TYPE {TYPE}"):
                try:
                    await cur.execute(s)
                except oracle.DatabaseError:
                    # best-effort drop of a table that may not exist
                    pass
        finally:
            await Conn.close()

    async def test_async_sessionless_suspend_resume(self):
        # Async mirror of SessionlessTransactionIntegration (#133): suspend on
        # one async connection, resume + commit on another. Skips below 23ai.
        from oracle.exceptions import NotSupportedError
        Kw = dict(self._kwargs()); Kw["autocommit"] = False
        table = "PYORACLE_ASL_TEST"
        setup = await oracle.connect_async(**Kw)
        c1 = c2 = None
        try:
            scur = setup.cursor()
            try:
                await scur.execute(f"DROP TABLE {table}")
            except oracle.DatabaseError as e:
                if e.code != 942:
                    raise
            await scur.execute(f"CREATE TABLE {table} (id NUMBER)")
            await setup.commit()
            try:
                await setup.begin_sessionless_transaction("aprobe", timeout=10)
            except NotSupportedError:
                self.skipTest("sessionless transactions need a 23ai+ server")
            await setup.suspend_sessionless_transaction()
            await setup.rollback()

            c1 = await oracle.connect_async(**Kw)
            await c1.begin_sessionless_transaction("asl-1", timeout=120)
            await c1.cursor().execute(f"INSERT INTO {table} VALUES (10)")
            await c1.suspend_sessionless_transaction()

            c2 = await oracle.connect_async(**Kw)
            await c2.resume_sessionless_transaction("asl-1", timeout=120)
            await c2.cursor().execute(f"INSERT INTO {table} VALUES (20)")
            await c2.commit()

            ccur = c2.cursor()
            await ccur.execute(f"SELECT id FROM {table} ORDER BY id")
            self.assertEqual(await ccur.fetchall(), [(10,), (20,)])
        finally:
            for c in (setup, c1, c2):
                if c is not None:
                    await c.close()


@unittest.skipUnless(
    _USER and os.environ.get("PYORACLE_TEST_BFILE_DIR"),
    "BFILE tests need PYORACLE_TEST_BFILE_DIR (Oracle DIRECTORY object "
    "name that already exists, with READ granted to the test user, plus "
    "a file named `pyoracle_bfile_test.txt` containing the text "
    "'hello bfile from disk'). The test user also needs EXECUTE on "
    "DBMS_LOB and CREATE PROCEDURE so the helper function can install "
    "itself on first call.",
)
class BFILEIntegration(unittest.TestCase):
    """Verify BFILE read round-trips."""

    def setUp(self):
        self.conn = oracle.connect(
            host=os.environ.get("PYORACLE_TEST_HOST", "localhost"),
            port=int(os.environ.get("PYORACLE_TEST_PORT", "1521")),
            user=os.environ["PYORACLE_TEST_USER"],
            password=os.environ["PYORACLE_TEST_PASSWORD"],
            service_name=os.environ.get("PYORACLE_TEST_SERVICE", "XE"),
            autocommit=True,
            **_FV_KW,
        )
        self.cur = self.conn.cursor()
        self.dir = os.environ["PYORACLE_TEST_BFILE_DIR"]

    def tearDown(self):
        self.conn.close()

    def test_bfile_select_returns_file_contents(self):
        # The user-facing path: a plain SELECT of a BFILE column returns
        # the file content as bytes (via the auto-resolve in Cursor.execute).
        self.cur.execute(
            "SELECT BFILENAME(:d, :f) FROM DUAL",
            {"d": self.dir, "f": _BFILE_TEST_FILE},
        )
        (Got,) = self.cur.fetchone()
        self.assertEqual(Got, _BFILE_TEST_CONTENT)

    def test_bfile_locator_parsing(self):
        # The LOB-object surface: directory_name / filename / is_file
        # attributes from the locator bytes. Auto-resolve has to be off
        # to see the LOB object before it's read.
        import oracle.cursor as _cm
        Saved = _cm._resolve_lobs
        _cm._resolve_lobs = lambda c, r: r
        try:
            self.cur.execute(
                "SELECT BFILENAME(:d, :f) FROM DUAL",
                {"d": self.dir, "f": _BFILE_TEST_FILE},
            )
            (Lob,) = self.cur.fetchone()
        finally:
            _cm._resolve_lobs = Saved
        self.assertTrue(Lob.is_file)
        self.assertTrue(Lob.is_binary)
        self.assertFalse(Lob.is_character)
        self.assertEqual(Lob.directory_name, self.dir)
        self.assertEqual(Lob.filename, _BFILE_TEST_FILE)


@unittest.skipUnless(
    _USER and os.environ.get("PYORACLE_TEST_BFILE_DIR"),
    "Async BFILE tests share the same fixture requirements as the "
    "sync BFILEIntegration.",
)
class AsyncBFILEIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_async_bfile_select_returns_file_contents(self):
        Dir = os.environ["PYORACLE_TEST_BFILE_DIR"]
        async with await oracle.connect_async(
            host=_HOST, port=_PORT,
            user=_USER, password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
        ) as Conn:
            async with Conn.cursor() as Cur:
                await Cur.execute(
                    "SELECT BFILENAME(:d, :f) FROM DUAL",
                    {"d": Dir, "f": _BFILE_TEST_FILE},
                )
                (Got,) = await Cur.fetchone()
                self.assertEqual(Got, _BFILE_TEST_CONTENT)


@unittest.skipUnless(_USER, _SKIP_REASON)
class AsyncPoolIntegration(unittest.IsolatedAsyncioTestCase):
    """AsyncPool: pre-warm, acquire / release, capacity, timeout,
    health-check on dead connection."""

    def _kwargs(self, **extra):
        return dict(
            host=_HOST, port=_PORT,
            user=_USER, password=_PASSWORD,
            service_name=_SERVICE,
            autocommit=True,
            **_FV_KW,
            **extra,
        )

    async def test_pre_warms_to_min_and_runs_query(self):
        Pool = await oracle.create_pool_async(min=2, max=3, **self._kwargs())
        try:
            self.assertEqual(Pool.opened, 2)
            self.assertEqual(Pool.busy, 0)
            async with Pool.acquire() as Conn:
                self.assertEqual(Pool.busy, 1)
                Cur = Conn.cursor()
                await Cur.execute("SELECT 1 FROM dual")
                self.assertEqual(await Cur.fetchone(), (1,))
            self.assertEqual(Pool.busy, 0)
        finally:
            await Pool.close()

    async def test_grows_to_max_and_releases_for_reuse(self):
        Pool = await oracle.create_pool_async(min=1, max=3, **self._kwargs())
        try:
            G1 = Pool.acquire(); await G1.__aenter__()
            G2 = Pool.acquire(); await G2.__aenter__()
            G3 = Pool.acquire(); await G3.__aenter__()
            self.assertEqual(Pool.busy, 3)
            self.assertEqual(Pool.opened, 3)
            await G1.__aexit__(None, None, None)
            self.assertEqual(Pool.busy, 2)
            async with Pool.acquire():
                # Pool reused the released entry; should NOT have grown.
                self.assertEqual(Pool.busy, 3)
                self.assertEqual(Pool.opened, 3)
            await G2.__aexit__(None, None, None)
            await G3.__aexit__(None, None, None)
        finally:
            await Pool.close()

    async def test_acquire_times_out_when_full(self):
        Pool = await oracle.create_pool_async(
            min=1, max=1, timeout=0.3, **self._kwargs(),
        )
        try:
            async with Pool.acquire():
                with self.assertRaises(oracle.InterfaceError):
                    async with Pool.acquire():
                        pass
        finally:
            await Pool.close()

    async def test_acquire_after_close_raises(self):
        Pool = await oracle.create_pool_async(min=1, max=2, **self._kwargs())
        await Pool.close()
        with self.assertRaises(oracle.InterfaceError):
            async with Pool.acquire():
                pass

    async def test_health_check_replaces_dead_connection(self):
        Pool = await oracle.create_pool_async(
            min=1, max=2, idle_timeout=0, **self._kwargs(),
        )
        try:
            G = Pool.acquire()
            Conn = await G.__aenter__()
            await G.__aexit__(None, None, None)
            # Sabotage the underlying writer to force the next health-check
            # to see a dead session.
            try:
                Conn._writer.close()
                await Conn._writer.wait_closed()
            except Exception:
                # Best-effort: deliberately sabotaging the writer for the
                # test; any close error here is irrelevant.
                pass
            async with Pool.acquire() as Conn2:
                Cur = Conn2.cursor()
                await Cur.execute("SELECT 1 FROM dual")
                self.assertEqual(await Cur.fetchone(), (1,))
        finally:
            await Pool.close()


@unittest.skipUnless(_USER, _SKIP_REASON)
class SSLIntegration(unittest.TestCase):
    """Verify the TLS wrap by talking to Oracle through a local TLS proxy.

    The proxy terminates TLS on a random local port and forwards plaintext
    to the configured Oracle listener, so we can exercise the full TLS
    handshake + encrypted TNS exchange without reconfiguring Oracle itself.
    """

    @classmethod
    def setUpClass(cls):
        cls.proxy = TLSProxy(_HOST, _PORT)
        cls.proxy.start()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proxy", None) is not None:
            cls.proxy.stop()
            cls.proxy = None

    def _connect_via_tls(self, **overrides):
        Kwargs = dict(
            host="127.0.0.1",
            port=self.proxy.listen_port,
            user=_USER, password=_PASSWORD, service_name=_SERVICE,
            autocommit=True,
            ssl={"ca_certs": CERT_PATH, "server_hostname": "localhost"},
        )
        Kwargs.update(overrides)
        return oracle.connect(**Kwargs)

    def test_tls_select_round_trip(self):
        with self._connect_via_tls() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 'tls works', 7 FROM dual")
            self.assertEqual(cur.fetchone(), ("tls works", 7))

    def test_tls_with_explicit_ssl_context(self):
        Ctx = ssl.create_default_context(cafile=CERT_PATH)
        with self._connect_via_tls(ssl=Ctx) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM dual")
            self.assertEqual(cur.fetchone(), (1,))

    def test_tls_no_ca_fails_handshake(self):
        # Default context with no extra trust → our self-signed cert is
        # rejected. The exact exception class is platform-dependent (SSLError
        # vs SSLCertVerificationError); both are subclasses of OSError.
        with self.assertRaises((ssl.SSLError, OSError)):
            self._connect_via_tls(ssl=True)

    def test_tls_hostname_mismatch_fails(self):
        # Cert SAN covers localhost / 127.0.0.1; pretend we asked for a
        # different hostname and expect the cert to fail verification.
        with self.assertRaises((ssl.SSLError, OSError)):
            self._connect_via_tls(
                ssl={"ca_certs": CERT_PATH, "server_hostname": "elsewhere.test"},
            )

    def test_tls_verify_disabled_accepts_self_signed(self):
        with self._connect_via_tls(
            ssl={"check_hostname": False, "verify_mode": ssl.CERT_NONE},
        ) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 'no-verify' FROM dual")
            self.assertEqual(cur.fetchone(), ("no-verify",))

    def test_tls_unknown_option_rejected(self):
        with self.assertRaises(ValueError):
            self._connect_via_tls(ssl={"ca_certs": CERT_PATH,
                                       "server_hostname": "localhost",
                                       "made_up_option": True})

    def test_ssl_none_still_plain(self):
        # Connecting directly to the plaintext Oracle port with ssl=None
        # should work unchanged — this guards against regressions in the
        # default code path.
        with oracle.connect(host=_HOST, port=_PORT, user=_USER,
                            password=_PASSWORD, service_name=_SERVICE,
                            autocommit=True, **_FV_KW) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM dual")
            self.assertEqual(cur.fetchone(), (1,))


@unittest.skipUnless(_USER, _SKIP_REASON)
class CallprocIntegration(_IntegrationBase):
    """OUT / IN OUT binds via cursor.var + callproc against a real procedure."""

    PROC = "PYORACLE_TEST_PROC"

    def tearDown(self):
        try:
            c = self.conn.cursor()
            try:
                c.execute(f"DROP PROCEDURE {self.PROC}")
            except oracle.DatabaseError:
                pass            # ORA-04043: procedure does not exist
            finally:
                c.close()
        finally:
            super().tearDown()

    def _make(self, signature_and_body: str):
        self.cur.execute(
            f"CREATE OR REPLACE PROCEDURE {self.PROC} {signature_and_body}")

    def test_callproc_out(self):
        self._make("(p_in IN NUMBER, p_out OUT NUMBER) AS "
                   "BEGIN p_out := p_in * 2; END;")
        o = self.cur.var(int)
        ret = self.cur.callproc(self.PROC, [21, o])
        self.assertEqual(o.getvalue(), 42)
        self.assertEqual(ret, [21, 42])

    def test_callproc_inout(self):
        self._make("(p_io IN OUT VARCHAR2) AS "
                   "BEGIN p_io := p_io || '!'; END;")
        io = self.cur.var(str)
        io.setvalue(0, "hi")
        ret = self.cur.callproc(self.PROC, [io])
        self.assertEqual(io.getvalue(), "hi!")
        self.assertEqual(ret, ["hi!"])

    def test_callproc_out_and_inout(self):
        self._make("(p_in IN NUMBER, p_out OUT NUMBER, p_io IN OUT VARCHAR2) AS "
                   "BEGIN p_out := p_in * 2; p_io := p_io || '!'; END;")
        o = self.cur.var(oracle.NUMBER)
        io = self.cur.var(oracle.STRING)
        io.setvalue(0, "hi")
        ret = self.cur.callproc(self.PROC, [5, o, io])
        self.assertEqual(ret, [5, 10, "hi!"])

    def test_callproc_string_out(self):
        self._make("(p OUT VARCHAR2) AS BEGIN p := 'pyoracle'; END;")
        s = self.cur.var(str)
        self.cur.callproc(self.PROC, [s])
        self.assertEqual(s.getvalue(), "pyoracle")

    def test_null_scalar_out_bind(self):
        # A NULL scalar OUT bind: the IOV return code is a variable-length int
        # (ub4(-1) = 2 bytes for NULL vs one 0x00 byte for non-NULL), so a fixed
        # 1-byte skip desynced the decoder (#205). A mix of NULL and non-NULL
        # OUT binds in one block must all decode.
        a, b, c = (self.cur.var(str) for _ in range(3))
        self.cur.execute("BEGIN :1 := 'x'; :2 := NULL; :3 := 'z'; END;",
                         [a, b, c])
        self.assertEqual((a.getvalue(), b.getvalue(), c.getvalue()),
                         ("x", None, "z"))
        only = self.cur.var(str)
        self.cur.execute("BEGIN :1 := NULL; END;", [only])
        self.assertIsNone(only.getvalue())

    def test_execute_out_var(self):
        y = self.cur.var(oracle.NUMBER)
        self.cur.execute("BEGIN :y := 7 * 6; END;", [y])
        self.assertEqual(y.getvalue(), 42)

    def test_callproc_refcursor(self):
        self._make(
            "(p_rc OUT SYS_REFCURSOR) AS BEGIN OPEN p_rc FOR "
            "SELECT 1 AS a, 'x' AS b FROM dual "
            "UNION ALL SELECT 2, 'y' FROM dual; END;")
        rc = self.cur.var(oracle.CURSOR)
        self.cur.callproc(self.PROC, [rc])
        nested = rc.getvalue()
        self.assertEqual([d[0] for d in nested.description], ["A", "B"])
        self.assertEqual(nested.fetchall(), [(1, "x"), (2, "y")])

    def test_callfunc_number(self):
        fn = f"{self.PROC}_F"
        self.cur.execute(
            f"CREATE OR REPLACE FUNCTION {fn}(p IN NUMBER) RETURN NUMBER AS "
            "BEGIN RETURN p + 100; END;")
        try:
            self.assertEqual(self.cur.callfunc(fn, oracle.NUMBER, [5]), 105)
            self.assertEqual(self.cur.callfunc(fn, int, [0]), 100)
        finally:
            self.cur.execute(f"DROP FUNCTION {fn}")

    def test_callfunc_string(self):
        fn = f"{self.PROC}_F"
        self.cur.execute(
            f"CREATE OR REPLACE FUNCTION {fn}(p IN NUMBER, q IN VARCHAR2) "
            "RETURN VARCHAR2 AS BEGIN RETURN q || ':' || TO_CHAR(p * 2); END;")
        try:
            self.assertEqual(self.cur.callfunc(fn, str, [21, "x"]), "x:42")
        finally:
            self.cur.execute(f"DROP FUNCTION {fn}")

    # ----- OUT binds for the extended scalar types (issue #17) -----

    def test_callproc_out_timestamp(self):
        self._make("(p OUT TIMESTAMP) AS BEGIN "
                   "p := TIMESTAMP '2026-06-07 13:14:15.5'; END;")
        v = self.cur.var(oracle.DB_TYPE_TIMESTAMP)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(v.getvalue(),
                         datetime.datetime(2026, 6, 7, 13, 14, 15, 500000))

    def test_callproc_out_timestamp_tz(self):
        self._make("(p OUT TIMESTAMP WITH TIME ZONE) AS BEGIN "
                   "p := TIMESTAMP '2026-06-07 13:14:15.5 +02:00'; END;")
        v = self.cur.var(oracle.DB_TYPE_TIMESTAMP_TZ)
        self.cur.callproc(self.PROC, [v])
        got = v.getvalue()
        self.assertEqual(got.utcoffset(), datetime.timedelta(hours=2))
        self.assertEqual(got.replace(tzinfo=None),
                         datetime.datetime(2026, 6, 7, 13, 14, 15, 500000))

    def test_callproc_out_binary_float(self):
        self._make("(p OUT BINARY_FLOAT) AS BEGIN p := 1.5; END;")
        v = self.cur.var(oracle.DB_TYPE_BINARY_FLOAT)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(v.getvalue(), 1.5)

    def test_callproc_out_binary_double(self):
        self._make("(p OUT BINARY_DOUBLE) AS BEGIN p := 2.25; END;")
        v = self.cur.var(oracle.DB_TYPE_BINARY_DOUBLE)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(v.getvalue(), 2.25)

    def test_callproc_out_interval_ds(self):
        self._make("(p OUT INTERVAL DAY TO SECOND) AS BEGIN "
                   "p := INTERVAL '1 02:03:04.5' DAY TO SECOND; END;")
        v = self.cur.var(oracle.DB_TYPE_INTERVAL_DS)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(
            v.getvalue(),
            datetime.timedelta(days=1, hours=2, minutes=3, seconds=4,
                               milliseconds=500))

    def test_callproc_out_interval_ym(self):
        self._make("(p OUT INTERVAL YEAR TO MONTH) AS BEGIN "
                   "p := INTERVAL '3-7' YEAR TO MONTH; END;")
        v = self.cur.var(oracle.DB_TYPE_INTERVAL_YM)
        self.cur.callproc(self.PROC, [v])
        self.assertEqual(v.getvalue(), oracle.IntervalYM(3, 7))

    def test_callfunc_binary_double(self):
        fn = f"{self.PROC}_F"
        self.cur.execute(
            f"CREATE OR REPLACE FUNCTION {fn} RETURN BINARY_DOUBLE AS "
            "BEGIN RETURN 9.875; END;")
        try:
            self.assertEqual(
                self.cur.callfunc(fn, oracle.DB_TYPE_BINARY_DOUBLE), 9.875)
        finally:
            self.cur.execute(f"DROP FUNCTION {fn}")


if __name__ == "__main__":
    unittest.main()
