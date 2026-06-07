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
from oracle import BinaryDouble, BinaryFloat, IntervalYM

# Resolve the TLS proxy fixture without depending on the `tests` package
# layout (works under both `python -m unittest tests.test_integration` and
# discovery from the repo root).
import sys as _sys
_sys.path.insert(0, os.path.dirname(__file__))
from _tls_proxy import CERT_PATH, TLSProxy  # noqa: E402


_USER = os.environ.get('PYORACLE_TEST_USER')
_PASSWORD = os.environ.get('PYORACLE_TEST_PASSWORD', '')
_HOST = os.environ.get('PYORACLE_TEST_HOST', 'localhost')
_PORT = int(os.environ.get('PYORACLE_TEST_PORT', '1521'))
_SERVICE = os.environ.get('PYORACLE_TEST_SERVICE', 'XE')

_SKIP_REASON = (
    "integration tests require a real DB connection; "
    "set PYORACLE_TEST_USER (and PYORACLE_TEST_PASSWORD) to enable"
)


def _connect():
    # Oracle XE's listener throttles rapid logins. A short pause between
    # connections keeps the suite below the throttle threshold; see
    # `_IntegrationBase` docstring for the full story.
    import time
    time.sleep(0.05)
    return oracle.connect(
        host=_HOST, port=_PORT,
        user=_USER, password=_PASSWORD,
        service_name=_SERVICE,
        autocommit=True,
    )


class _IntegrationBase(unittest.TestCase):
    """Per-test connection; fresh cursor + scratch table per test.

    Oracle XE's listener throttles rapid logins ("logon storm"
    protection) and occasionally cancels the first statement on a
    just-opened session with ORA-01013 ("user requested cancel of
    current operation"). This is documented server behaviour, not a
    driver bug — production code uses connection pools (`oracle.Pool`,
    issue #6) and doesn't hit it. To keep the integration suite
    deterministic, `setUp` retries the connect / initial-drop dance
    a few times on ORA-01013.
    """
    TABLE = "PYORACLE_TEST"

    def setUp(self):
        Last = None
        for _ in range(5):
            try:
                self.conn = _connect()
                self.cur = self.conn.cursor()
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
                    pass
                import time
                time.sleep(0.05)
        raise Last

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

    def test_char_preserves_padding(self):
        v = self._round_trip("CHAR(10)", "'x'")
        self.assertEqual(v, "x" + " " * 9)
        self.assertEqual(len(v), 10)

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
        self.assertEqual(v, IntervalYM(3, 7))
        self.assertIsInstance(v, IntervalYM)

    def test_interval_ym_negative(self):
        v = self._round_trip("INTERVAL YEAR(4) TO MONTH",
                             "INTERVAL '-1-2' YEAR TO MONTH")
        self.assertEqual(v, IntervalYM(-1, -2))

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
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        import oracle.connection as _c
        orig = _c.OracleConnect.send
        sends = [0]
        _c.OracleConnect.send = lambda s, T, D: (
            sends.__setitem__(0, sends[0] + 1), orig(s, T, D))[1]
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
                         [BinaryFloat(-2.25)])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (-2.25,))

    def test_binary_double_bind(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (v BINARY_DOUBLE)")
        self.cur.execute(f"INSERT INTO {self.TABLE} VALUES (:1)",
                         [BinaryDouble(1234.5678)])
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
                         [IntervalYM(3, 7)])
        self.cur.execute(f"SELECT v FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchone(), (IntervalYM(3, 7),))

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
class ErrorAndRowcountIntegration(_IntegrationBase):
    """Verify that DatabaseError carries the server's message text and that
    Cursor.rowcount reflects the affected-row count from the OER block."""

    def test_error_message_includes_ora_text(self):
        with self.assertRaises(oracle.DatabaseError) as ctx:
            self.cur.execute(f"SELECT * FROM nope_{os.getpid()}_xyz")
        # Exception code: the ORA number; str(): the full server message.
        self.assertEqual(ctx.exception.code, 942)
        self.assertIn("ORA-00942", str(ctx.exception))
        self.assertIn("table or view does not exist", str(ctx.exception))

    def test_error_message_for_invalid_number(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER)")
        with self.assertRaises(oracle.DatabaseError) as ctx:
            self.cur.execute(f"INSERT INTO {self.TABLE} VALUES ('not-a-number')")
        self.assertEqual(ctx.exception.code, 1722)
        self.assertIn("ORA-01722", str(ctx.exception))
        self.assertIn("invalid number", str(ctx.exception))

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

    def test_repeated_dml_reuses_cursor(self):
        self.cur.execute(f"CREATE TABLE {self.TABLE} (id NUMBER, v VARCHAR2(10))")
        Sql = f"INSERT INTO {self.TABLE} VALUES (:id, :v)"
        # First execute: parses + caches.
        self.cur.execute(Sql, {"id": 1, "v": "a"})
        self.assertIn(Sql, self.conn._cursor_cache)
        FirstCursor = self.conn._cursor_cache[Sql]
        self.assertGreater(FirstCursor, 0)
        # Second execute of identical SQL: same cached handle.
        self.cur.execute(Sql, {"id": 2, "v": "b"})
        self.assertEqual(self.conn._cursor_cache[Sql], FirstCursor)
        # Different SQL → different cache entry.
        Sql2 = f"UPDATE {self.TABLE} SET v = :v WHERE id = 1"
        self.cur.execute(Sql2, {"v": "z"})
        self.assertIn(Sql2, self.conn._cursor_cache)
        self.assertNotEqual(
            self.conn._cursor_cache[Sql], self.conn._cursor_cache[Sql2]
        )
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
        self.assertIn(Latest, self.conn._cursor_cache)
        self.assertNotIn(Earliest, self.conn._cursor_cache)


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
                pass
            # Next acquire must succeed (with a fresh connection,
            # ping caught the dead one).
            with Pool.acquire() as Conn2:
                Cur = Conn2.cursor()
                Cur.execute("SELECT 1 FROM dual")
                self.assertEqual(Cur.fetchone(), (1,))
        finally:
            Pool.close()


_BFILE_TEST_DIR = "PYORACLE_BFILE_TEST_DIR"
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
        )

    async def test_connect_and_simple_query(self):
        Conn = await oracle.connect_async(**self._kwargs())
        try:
            Cur = Conn.cursor()
            await Cur.execute("SELECT 1 FROM dual")
            self.assertEqual(await Cur.fetchone(), (1,))
            await Cur.close()
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
            async with Conn.cursor() as Cur:
                await Cur.execute("CREATE TABLE PYORACLE_ASYNC_SCROLL (id NUMBER)")
                try:
                    await Cur.executemany(
                        "INSERT INTO PYORACLE_ASYNC_SCROLL VALUES (:1)",
                        [(i,) for i in range(1, 11)])
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
                            autocommit=True) as conn:
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
