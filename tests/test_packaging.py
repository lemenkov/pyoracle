# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The released distribution is the client driver only.

The Mirror server (``seerdb.server``) ships in the repository but must NOT land
in the built package, and importing ``seerdb`` must never require it.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent


def test_import_seerdb_does_not_eagerly_load_the_mirror() -> None:
    # A fresh interpreter: `import seerdb` must not pull in seerdb.server (so a
    # client-only install with no server subpackage imports cleanly), yet the
    # lazy API is still reachable when the subpackage is present.
    code = (
        'import sys, seerdb;'
        "assert 'seerdb.server' not in sys.modules, 'server loaded eagerly';"
        'assert callable(seerdb.connect);'
        'assert callable(seerdb.serve) and isinstance(seerdb.Server, type);'
        "assert 'seerdb.server' in sys.modules, 'lazy access should load it';"
        "print('ok')"
    )
    result = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True, cwd=_ROOT
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'ok'


def test_pyproject_excludes_the_mirror() -> None:
    # A cheap tripwire so the exclusion is not silently dropped from packaging.
    assert 'seerdb.server*' in (_ROOT / 'pyproject.toml').read_text()


def test_built_sdist_ships_the_client_not_the_mirror(tmp_path) -> None:
    pytest.importorskip('build')
    subprocess.run(
        [
            sys.executable,
            '-m',
            'build',
            '--sdist',
            '--no-isolation',
            '--outdir',
            str(tmp_path),
        ],
        cwd=_ROOT,
        check=True,
        capture_output=True,
    )
    (sdist,) = tmp_path.glob('*.tar.gz')
    with tarfile.open(sdist) as tar:
        names = tar.getnames()

    def ships(subpackage: str) -> bool:
        return any(f'/seerdb/{subpackage}/' in name for name in names)

    assert ships('client'), 'client driver missing from the sdist'
    assert ships('common'), 'common codec missing from the sdist'
    assert not ships('server'), 'the Mirror must NOT ship in the distribution'
