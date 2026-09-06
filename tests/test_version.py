# SPDX-FileCopyrightText: 2025 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT
"""`seerdb.__version__` is the version the package declares and sends."""

import re
import unittest
from pathlib import Path

import seerdb
from seerdb.common.tns import _CLIENT_VERSION


class TestVersion(unittest.TestCase):
    def test_module_version_is_the_wire_version(self):
        self.assertEqual(seerdb.__version__, _CLIENT_VERSION)

    def test_module_version_is_the_package_version(self):
        pyproject = (
            Path(__file__).resolve().parent.parent / 'pyproject.toml'
        ).read_text()
        declared = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE).group(1)
        self.assertEqual(seerdb.__version__, declared)
