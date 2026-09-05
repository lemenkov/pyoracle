# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the client-side SQL-text parsers (#439).

``is_plsql`` classifies a statement as a PL/SQL block (so execute picks the
anonymous-block path and the temp-LOB promotion), and ``extract_bind_names``
pulls the ``:name`` placeholders a dict bind is matched against. Both must see
through leading comments and quoted text.

A placeholder name is returned in its lookup form: an unquoted one folds to
upper, since it is case-insensitive, while a quoted ``:"name"`` keeps its exact
text, since it is not (#686). The scenarios (comment-led
SELECT/DML/PLSQL classification and named-bind extraction) mirror the go-ora
driver's statement/parse tests (MIT), reused as facts; the assertions are
original.
"""

import unittest

from seerdb.client.cursor import _resolve_parameters
from seerdb.common.sqltext import (
    bind_placeholders,
    canonical_bind_key,
    extract_bind_names,
    is_plsql,
    is_reusable_dml,
)


class TestIsPlsql(unittest.TestCase):
    def test_plain_block_forms(self):
        self.assertTrue(is_plsql('BEGIN null; END;'))
        self.assertTrue(is_plsql('DECLARE x number; BEGIN null; END;'))

    def test_case_insensitive_and_leading_whitespace(self):
        self.assertTrue(is_plsql('  begin null; end;'))
        self.assertTrue(is_plsql('\n\t declare x number; begin null; end;'))

    def test_leading_line_comments_before_block(self):
        # `--` line comments preceding BEGIN/DECLARE are stripped first.
        self.assertTrue(is_plsql('-- comment #1\n-- comment #2\nBEGIN null; END;'))

    def test_leading_block_comments_before_block(self):
        # `/* ... */` block comments (including multi-line) are stripped first.
        self.assertTrue(is_plsql('/* comment */ BEGIN null; END;'))
        self.assertTrue(
            is_plsql('/* multi\nline */\nDECLARE x number; BEGIN null; END;')
        )

    def test_mixed_comments_before_declare_block(self):
        sql = (
            '-- comment #1\n  -- comment #2\n/* comment #3 */\n'
            '  /* comment #4 */\nDECLARE\n  foo NUMBER := 42;\n'
            'BEGIN\n  INSERT INTO bar VALUES (foo);\nEND;\n'
        )
        self.assertTrue(is_plsql(sql))

    def test_comment_led_select_is_not_plsql(self):
        sql = '-- comment #1\n/* comment #2 */ select * from dual'
        self.assertFalse(is_plsql(sql))

    def test_comment_led_dml_is_not_plsql(self):
        sql = '/* comment */ update foo set bar = 1 where baz = 1'
        self.assertFalse(is_plsql(sql))

    def test_a_word_starting_with_begin_is_not_a_block(self):
        # `beginning` must not be mistaken for the BEGIN keyword.
        self.assertFalse(is_plsql('select beginning from t'))


class TestExtractBindNames(unittest.TestCase):
    def test_named_placeholders_in_order(self):
        sql = (
            'INSERT INTO TTB_NESTED_UDT(ID, DATA1, SEP1, DATA2, SEP2)\n'
            'VALUES(:ID, :DATA1, :SEP1, :DATA2, :SEP2)'
        )
        self.assertEqual(
            extract_bind_names(sql), ['ID', 'DATA1', 'SEP1', 'DATA2', 'SEP2']
        )

    def test_colons_inside_string_and_quoted_ident_are_ignored(self):
        sql = 'select \':notabind\', "col:notabind", :real from dual'
        self.assertEqual(extract_bind_names(sql), ['REAL'])

    def test_colons_inside_comments_are_ignored(self):
        sql = 'select :a /* :b */ , :c -- :d\nfrom dual'
        self.assertEqual(extract_bind_names(sql), ['A', 'C'])

    def test_dml_path_keeps_every_occurrence(self):
        # Plain SQL: Oracle expects one bind value per textual occurrence.
        self.assertEqual(
            extract_bind_names('select :x, :x, :y from dual'), ['X', 'X', 'Y']
        )

    def test_plsql_path_dedupes_repeats(self):
        # A PL/SQL block reuses one value per named placeholder.
        self.assertEqual(
            extract_bind_names('begin proc(:x, :x, :y); end;', dedupe=True),
            ['X', 'Y'],
        )

    def test_numeric_placeholders_are_not_named_binds(self):
        # `:1` positionals are not `:name` binds (a dict never names them).
        self.assertEqual(extract_bind_names('select :1, :name from dual'), ['NAME'])


class TestQuotedBindPlaceholders(unittest.TestCase):
    """`:"name"` — the spelling that reaches a name the plain form cannot (#686).

    A reserved word, or a name starting with a digit, is rejected outright as an
    unquoted placeholder, and quoting is how it gets through. Unlike the plain
    form it is case-sensitive, so the two spellings live in one namespace but
    fold differently.
    """

    def test_quoted_name_is_found(self):
        self.assertEqual(extract_bind_names('select :"p" from dual'), ['p'])

    def test_quoted_name_keeps_its_case(self):
        self.assertEqual(extract_bind_names('select :"p", :"P" from dual'), ['p', 'P'])

    def test_quoted_and_plain_are_told_apart(self):
        # Both fold to the same string, so the spelling is what distinguishes
        # them. This is the pair that a name alone cannot resolve.
        self.assertEqual(
            bind_placeholders('select :"P", :p from dual'),
            [('P', True), ('P', False)],
        )

    def test_names_the_plain_form_cannot_express(self):
        self.assertEqual(extract_bind_names('select :"desc" from dual'), ['desc'])
        self.assertEqual(extract_bind_names('select :"2x" from dual'), ['2x'])

    def test_a_quoted_identifier_is_still_not_a_bind(self):
        # The closing quote of a bind name must not open an identifier and
        # swallow the rest of the statement, which is what a naive scan does.
        sql = 'insert into "T" ("C") values (:"a") returning "C" into :"b"'
        self.assertEqual(extract_bind_names(sql), ['a', 'b'])

    def test_quoted_name_inside_a_string_literal_is_ignored(self):
        sql = 'select \':"a"\', :"b" from dual'
        self.assertEqual(extract_bind_names(sql), ['b'])


class TestBindKeyMatching(unittest.TestCase):
    """Which caller-supplied keys reach which placeholder.

    Matches python-oracledb: an unquoted key folds to upper, a quoted one is
    taken literally. So `:"P"` is reachable as both `'"P"'` and `'p'`, while
    `:"p"` is reachable only as `'"p"'`.
    """

    def test_key_forms(self):
        self.assertEqual(canonical_bind_key('p'), 'P')
        self.assertEqual(canonical_bind_key('"p"'), 'p')
        self.assertEqual(canonical_bind_key('"P"'), 'P')

    def test_upper_quoted_placeholder_accepts_either_spelling(self):
        sql = 'select :"P" from dual'
        for key in ('"P"', 'P', 'p'):
            self.assertEqual(_resolve_parameters(sql, {key: 1}), [1], key)

    def test_lower_quoted_placeholder_needs_the_quoted_key(self):
        sql = 'select :"p" from dual'
        self.assertEqual(_resolve_parameters(sql, {'"p"': 1}), [1])
        for key in ('p', 'P', '"P"'):
            with self.assertRaises(Exception) as ctx:
                _resolve_parameters(sql, {key: 1})
            self.assertIn(':"p"', str(ctx.exception))

    def test_plain_placeholder_rejects_a_quoted_key(self):
        with self.assertRaises(Exception):
            _resolve_parameters('select :q from dual', {'"q"': 1})

    def test_a_quoted_and_a_plain_bind_in_one_statement(self):
        self.assertEqual(
            _resolve_parameters('select :"a" + :b from dual', {'"a"': 1, 'b': 2}),
            [1, 2],
        )


class TestReusableDml(unittest.TestCase):
    """Which statements may have their server cursor reused (#703).

    Reusing a cursor is a parse saved: the statement is parsed once and executed
    again per set of bind values. That is true of DML and of nothing else. DDL
    does its work when the server *parses* it, so a re-execute has nothing left
    to do -- the server reports success and the statement never happens, without
    raising anything. A `CREATE TABLE` issued twice silently created nothing the
    second time, on every server old enough to use the cache.
    """

    def test_the_four_that_may_be_reused(self):
        for sql in (
            'insert into t values (1)',
            'UPDATE t SET a = 1',
            'delete from t where id = 1',
            'merge into t using s on (t.id = s.id) when matched then update set a = 1',
        ):
            self.assertTrue(is_reusable_dml(sql), sql)

    def test_ddl_may_not_be(self):
        for sql in (
            'create table t (id number)',
            'drop table t',
            'alter table t add c number',
            'truncate table t',
            'create or replace view v as select 1 from dual',
            "comment on table t is 'x'",
            'grant select on t to someone',
            'rename t to u',
        ):
            self.assertFalse(is_reusable_dml(sql), sql)

    def test_leading_comments_and_whitespace_do_not_hide_the_verb(self):
        self.assertTrue(is_reusable_dml('  /* note */ insert into t values (1)'))
        self.assertFalse(is_reusable_dml('  -- note\ncreate table t (id number)'))

    def test_anything_unrecognised_is_excluded(self):
        # Wrong in this direction costs a re-parse; wrong in the other loses the
        # statement, so the default has to be "do not reuse".
        for sql in ('call p()', 'explain plan for select 1 from dual', 'commit', ''):
            self.assertFalse(is_reusable_dml(sql), sql)


if __name__ == '__main__':
    unittest.main()
