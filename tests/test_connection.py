# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import unittest
from oracle.connection import OracleConnect

class TestConnection(unittest.TestCase):

    def test_basic(self):
        con = OracleConnect()
        self.assertTrue(con.connect())
