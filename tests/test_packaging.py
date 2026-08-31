# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""The released distribution is the client driver only.

The Mirror server (``seerdb.server``) ships in the repository but must NOT land
in the built package, and importing ``seerdb`` must never require it.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_PKG = _ROOT / 'seerdb'


def _imported_subpackages(module_path: Path) -> set[str]:
    # Every seerdb subpackage (`client` / `common` / `server`) this module
    # imports from, whether written `from seerdb.common...`, `from seerdb import
    # common`, or a relative `from ..common...`. TYPE_CHECKING-only imports count
    # too: the layering must hold in the type graph, not just at runtime.
    rel = module_path.relative_to(_PKG).parts  # e.g. ('common', 'tns.py')
    here = rel[0]
    tree = ast.parse(module_path.read_text(), filename=str(module_path))
    found: set[str] = set()

    def note(dotted: str) -> None:
        parts = dotted.split('.')
        if parts[0] == 'seerdb' and len(parts) > 1:
            found.add(parts[1])

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                note(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                note(node.module or '')
            elif node.level == 1:
                # `from . import common` inside seerdb/<here>/ -> sibling subpkg
                for alias in node.names:
                    found.add(alias.name)
            elif node.level == 2:
                # `from ..common import X` -> the named subpackage
                if node.module:
                    found.add(node.module.split('.')[0])
    found.discard(here)
    return found


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


# Which subpackage may import which. `common` is the shared codec leaf: it must
# depend on neither the client nor the Mirror. The client and the Mirror both
# build on `common` but never on each other, so the Mirror stays fully
# decoupled from the DB-API client (and vice versa).
_FORBIDDEN_EDGES = {
    'common': {'client', 'server'},
    'client': {'server'},
    'server': {'client'},
}


@pytest.mark.parametrize('layer', sorted(_FORBIDDEN_EDGES))
def test_subpackage_layering_is_enforced(layer: str) -> None:
    forbidden = _FORBIDDEN_EDGES[layer]
    violations = []
    for module_path in sorted((_PKG / layer).rglob('*.py')):
        bad = _imported_subpackages(module_path) & forbidden
        if bad:
            rel = module_path.relative_to(_ROOT)
            violations.append(f'{rel} imports from {sorted(bad)}')
    assert not violations, 'subpackage layering violated:\n' + '\n'.join(violations)
