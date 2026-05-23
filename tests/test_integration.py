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
import unittest
from decimal import Decimal

import oracle


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


if __name__ == "__main__":
    unittest.main()
