# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Offline tests for the client-side SQL-text parsers (#439).

``_is_plsql`` classifies a statement as a PL/SQL block (so execute picks the
anonymous-block path and the temp-LOB promotion), and ``_extract_bind_names``
pulls the ``:name`` placeholders a dict bind is matched against. Both must see
through leading comments and quoted text. The scenarios (comment-led
SELECT/DML/PLSQL classification and named-bind extraction) mirror the go-ora
driver's statement/parse tests (MIT), reused as facts; the assertions are
original.
"""

import unittest

from seerdb.client.cursor import _extract_bind_names, _is_plsql


class TestIsPlsql(unittest.TestCase):
    def test_plain_block_forms(self):
        self.assertTrue(_is_plsql('BEGIN null; END;'))
        self.assertTrue(_is_plsql('DECLARE x number; BEGIN null; END;'))

    def test_case_insensitive_and_leading_whitespace(self):
        self.assertTrue(_is_plsql('  begin null; end;'))
        self.assertTrue(_is_plsql('\n\t declare x number; begin null; end;'))

    def test_leading_line_comments_before_block(self):
        # `--` line comments preceding BEGIN/DECLARE are stripped first.
        self.assertTrue(_is_plsql('-- comment #1\n-- comment #2\nBEGIN null; END;'))

    def test_leading_block_comments_before_block(self):
        # `/* ... */` block comments (including multi-line) are stripped first.
        self.assertTrue(_is_plsql('/* comment */ BEGIN null; END;'))
        self.assertTrue(
            _is_plsql('/* multi\nline */\nDECLARE x number; BEGIN null; END;')
        )

    def test_mixed_comments_before_declare_block(self):
        sql = (
            '-- comment #1\n  -- comment #2\n/* comment #3 */\n'
            '  /* comment #4 */\nDECLARE\n  foo NUMBER := 42;\n'
            'BEGIN\n  INSERT INTO bar VALUES (foo);\nEND;\n'
        )
        self.assertTrue(_is_plsql(sql))

    def test_comment_led_select_is_not_plsql(self):
        sql = '-- comment #1\n/* comment #2 */ select * from dual'
        self.assertFalse(_is_plsql(sql))

    def test_comment_led_dml_is_not_plsql(self):
        sql = '/* comment */ update foo set bar = 1 where baz = 1'
        self.assertFalse(_is_plsql(sql))

    def test_a_word_starting_with_begin_is_not_a_block(self):
        # `beginning` must not be mistaken for the BEGIN keyword.
        self.assertFalse(_is_plsql('select beginning from t'))


class TestExtractBindNames(unittest.TestCase):
    def test_named_placeholders_in_order(self):
        sql = (
            'INSERT INTO TTB_NESTED_UDT(ID, DATA1, SEP1, DATA2, SEP2)\n'
            'VALUES(:ID, :DATA1, :SEP1, :DATA2, :SEP2)'
        )
        self.assertEqual(
            _extract_bind_names(sql), ['id', 'data1', 'sep1', 'data2', 'sep2']
        )

    def test_colons_inside_string_and_quoted_ident_are_ignored(self):
        sql = 'select \':notabind\', "col:notabind", :real from dual'
        self.assertEqual(_extract_bind_names(sql), ['real'])

    def test_colons_inside_comments_are_ignored(self):
        sql = 'select :a /* :b */ , :c -- :d\nfrom dual'
        self.assertEqual(_extract_bind_names(sql), ['a', 'c'])

    def test_dml_path_keeps_every_occurrence(self):
        # Plain SQL: Oracle expects one bind value per textual occurrence.
        self.assertEqual(
            _extract_bind_names('select :x, :x, :y from dual'), ['x', 'x', 'y']
        )

    def test_plsql_path_dedupes_repeats(self):
        # A PL/SQL block reuses one value per named placeholder.
        self.assertEqual(
            _extract_bind_names('begin proc(:x, :x, :y); end;', dedupe=True),
            ['x', 'y'],
        )

    def test_numeric_placeholders_are_not_named_binds(self):
        # `:1` positionals are not `:name` binds (a dict never names them).
        self.assertEqual(_extract_bind_names('select :1, :name from dual'), ['name'])


if __name__ == '__main__':
    unittest.main()
