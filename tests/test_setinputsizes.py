# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Declaring a bind's type when the value cannot say what it is (#696).

A bind's type is normally read off the value. That works until the value is
`None`, which carries no type: the server infers CHAR, and comparing that to a
DATE or NUMBER column is refused with ORA-00932. `setinputsizes` is how the
caller says what the value cannot, and it is also the mechanism SQLAlchemy uses
to type binds.

The declaration is applied by wrapping the bind in a `Var` of the declared type,
whose descriptor announces that type instead of guessing. Nothing here needs a
database — the wrapping is pure, and the descriptor it produces is checked
directly against the bytes a bind of that type sends.
"""

import datetime
import unittest
from decimal import Decimal

import seerdb
from seerdb.client._cursor_logic import _CursorLogic
from seerdb.common.datatypes import Var
from seerdb.common.tns import encode_token_oac
from seerdb.common.tns_consts import (
    TNS_TYPE_DATE,
    TNS_TYPE_NUMBER,
    TNS_TYPE_TIMESTAMP,
    TNS_TYPE_VARCHAR,
)


class _Logic(_CursorLogic):
    """The shared cursor logic alone, with no connection behind it."""

    def __init__(self):
        self._inputsizes = ((), {})


def _typed(sql, bind, *args, **kwargs):
    logic = _Logic()
    logic.setinputsizes(*args, **kwargs)
    return logic._typed_binds(sql, bind)


def _declared_type(bind):
    """The data type the bind's descriptor announces on the wire."""
    return encode_token_oac(bind)[0]


class TestDeclaringByPosition(unittest.TestCase):
    def test_a_positional_declaration_types_that_bind(self):
        [got] = _typed('select :1 from dual', [None], seerdb.DB_TYPE_DATE)
        self.assertIsInstance(got, Var)
        self.assertEqual(_declared_type(got), TNS_TYPE_DATE)

    def test_none_leaves_a_bind_alone(self):
        # PEP 249's way of saying "not this one".
        got = _typed('select :1, :2 from dual', ['a', None], None, seerdb.DB_TYPE_DATE)
        self.assertEqual(got[0], 'a')
        self.assertEqual(_declared_type(got[1]), TNS_TYPE_DATE)

    def test_more_declarations_than_binds_are_ignored(self):
        got = _typed(
            'select :1 from dual', [None], seerdb.DB_TYPE_DATE, seerdb.DB_TYPE_NUMBER
        )
        self.assertEqual(len(got), 1)


class TestDeclaringByName(unittest.TestCase):
    def test_a_named_declaration_finds_its_position(self):
        got = _typed('select :a, :b from dual', ['x', None], b=seerdb.DB_TYPE_DATE)
        self.assertEqual(got[0], 'x')
        self.assertEqual(_declared_type(got[1]), TNS_TYPE_DATE)

    def test_the_name_is_matched_case_insensitively(self):
        # An unquoted placeholder is case-insensitive, so a declaration for it
        # should be too.
        [got] = _typed('select :Foo from dual', [None], foo=seerdb.DB_TYPE_DATE)
        self.assertEqual(_declared_type(got), TNS_TYPE_DATE)

    def test_a_repeated_placeholder_types_every_occurrence(self):
        # Plain SQL sends one value per textual occurrence, so both need typing
        # or the second is still an untyped NULL.
        got = _typed(
            'select :a from t where :a is null', [None, None], a=seerdb.DB_TYPE_DATE
        )
        self.assertEqual([_declared_type(b) for b in got], [TNS_TYPE_DATE] * 2)


class TestWhatCanBeDeclared(unittest.TestCase):
    def test_a_python_type(self):
        [got] = _typed('select :1 from dual', [None], datetime.datetime)
        self.assertEqual(_declared_type(got), TNS_TYPE_DATE)

    def test_a_database_type(self):
        [got] = _typed('select :1 from dual', [None], seerdb.DB_TYPE_TIMESTAMP)
        self.assertEqual(_declared_type(got), TNS_TYPE_TIMESTAMP)

    def test_an_integer_declares_a_string_of_that_size(self):
        # What PEP 249's "size" means, and what python-oracledb does with one.
        [got] = _typed('select :1 from dual', ['x'], 40)
        self.assertEqual(_declared_type(got), TNS_TYPE_VARCHAR)
        self.assertEqual(got.size, 40)

    def test_a_declared_bind_keeps_its_value(self):
        # Declaring a type is not the same as discarding the value: a real value
        # still travels, it just travels as the declared type.
        [got] = _typed('select :1 from dual', [Decimal('1.5')], seerdb.DB_TYPE_NUMBER)
        self.assertEqual(_declared_type(got), TNS_TYPE_NUMBER)
        self.assertEqual(got.getvalue(), Decimal('1.5'))


class TestWhenItApplies(unittest.TestCase):
    def test_no_declaration_leaves_the_binds_untouched(self):
        bind = [None, 'x']
        self.assertIs(_typed('select :1, :2 from dual', bind), bind)

    def test_an_out_bind_keeps_its_own_type(self):
        # A Var already says what it is; a declaration must not replace it.
        receiver = Var(int)
        got = _typed('begin :1 := 1; end;', [receiver], seerdb.DB_TYPE_DATE)
        self.assertIs(got[0], receiver)

    def test_calling_it_with_nothing_discards_a_pending_declaration(self):
        logic = _Logic()
        logic.setinputsizes(seerdb.DB_TYPE_DATE)
        logic.setinputsizes()
        bind = [None]
        self.assertIs(logic._typed_binds('select :1 from dual', bind), bind)


if __name__ == '__main__':
    unittest.main()
