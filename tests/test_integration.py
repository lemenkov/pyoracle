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
import os
import ssl
import unittest
from decimal import Decimal

import oracle

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
    return oracle.connect(
        host=_HOST, port=_PORT,
        user=_USER, password=_PASSWORD,
        service_name=_SERVICE,
        autocommit=True,
    )


class _IntegrationBase(unittest.TestCase):
    """Per-test connection; fresh cursor + scratch table per test.

    The driver has known protocol-state issues that surface as transient
    ORA-01013 ("user requested cancel") errors when many statements run
    rapidly on the same connection. Per-test connections keep the failure
    rate low; the remaining flake should be investigated separately.
    """
    TABLE = "PYORACLE_TEST"

    def setUp(self):
        self.conn = _connect()
        self.cur = self.conn.cursor()
        self._drop_silently(self.cur)

    def tearDown(self):
        # The test may have closed self.cur — always reach for a fresh one.
        try:
            cleanup = self.conn.cursor()
            try:
                self._drop_silently(cleanup)
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
        # `:x` referenced twice in the SQL, but only one bind value is needed.
        self.cur.execute(f"CREATE TABLE {self.TABLE} (a NUMBER, b NUMBER)")
        self.cur.execute(
            f"INSERT INTO {self.TABLE} VALUES (:x, :x)", {"x": 42}
        )
        self.cur.execute(f"SELECT a, b FROM {self.TABLE}")
        self.assertEqual(self.cur.fetchall(), [(42, 42)])

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


if __name__ == "__main__":
    unittest.main()
