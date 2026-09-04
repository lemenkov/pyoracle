# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

"""Reading the bind placeholders out of a statement's text.

Both ends of the connection need this, and they need to agree. The client scans
a statement to work out which value goes where, and how many to send. The Mirror
scans the same statement to work out how many values to expect, because a
`RETURNING ... INTO` bind is filled by the server and so carries no value in the
row data -- read one for it and everything after it is misread
(docs/PROTOCOL.md 22). One implementation, so the two cannot drift.

Nothing here touches the wire. It is text analysis, kept beside the codec rather
than inside it.
"""

from __future__ import annotations

import re

# A `:name` placeholder, in either spelling. An unquoted name follows normal SQL
# identifier rules and is case-insensitive; pure-digit forms (`:1`, `:2`) are
# handled separately as positional indices.
#
# A quoted name (`:"name"`) is how a name the unquoted form cannot express gets
# through — a reserved word, or one starting with a digit — and unlike the
# unquoted form it is case-SENSITIVE, so `:"a"` and `:"A"` are two different
# placeholders (#686). Group 1 is the quoted name, group 2 the unquoted one.
_NAMED_BIND_RE = re.compile(r':(?:"([^"\n]+)"|([A-Za-z_]\w*))')
# The same, plus the numeric `:1` form. Used to count the placeholders after a
# RETURNING clause's INTO, where only how many there are matters.
_ANY_BIND_RE = re.compile(r':\s*(?:"[^"\n]+"|\w+)')


def _blank(Text: str) -> str:
    """Spaces of the same length, with newlines kept so line structure survives."""
    return ''.join(' ' if C != '\n' else C for C in Text)


def strip_non_bind_text(SQL: str) -> str:
    """SQL with everything a placeholder cannot appear inside blanked out.

    String literals and comments go, and so do quoted identifiers — but *not* a
    quoted bind name, which is a colon away from looking exactly like one.

    Blanked, not deleted: the result is the same length as the input, so an
    offset found here indexes the original text as well. `strip_returning_into`
    depends on that, and a statement carrying a comment would otherwise cut in
    the wrong place.
    """
    Cleaned = re.sub(r"'(?:''|[^'])*'", lambda M: _blank(M.group(0)), SQL)
    # One pass over both, so a quoted bind name is consumed whole rather than
    # leaving its closing quote to open a spurious identifier that then swallows
    # the rest of the statement. The first alternative wins where they overlap.
    Cleaned = re.sub(
        r'(:\s*"[^"\n]*")|"(?:""|[^"])*"',
        lambda M: M.group(1) or _blank(M.group(0)),
        Cleaned,
    )
    Cleaned = re.sub(r'--[^\n]*', lambda M: _blank(M.group(0)), Cleaned)
    return re.sub(r'/\*.*?\*/', lambda M: _blank(M.group(0)), Cleaned, flags=re.S)


def canonical_bind_key(Key: str) -> str:
    """The lookup form of a caller-supplied bind name.

    A key written with quotes means the quoted placeholder of that exact name;
    anything else is an unquoted placeholder, which is case-insensitive and so
    folds. Matches python-oracledb, where `:"P"` is reachable as both `'"P"'`
    and `'p'` while `:"p"` is reachable only as `'"p"'`.
    """
    if len(Key) > 2 and Key.startswith('"') and Key.endswith('"'):
        return Key[1:-1]
    return Key.upper()


def bind_placeholders(SQL: str, dedupe: bool = False) -> list[tuple[str, bool]]:
    # Every `:name` placeholder in left-to-right SQL order as (name, quoted),
    # with string literals, comments and quoted identifiers stripped so we don't
    # match inside them.
    #
    # The name is in its lookup form: an unquoted one folds to upper (it is
    # case-insensitive), a quoted one keeps its exact text (it is not). The flag
    # says which spelling it was, which is what tells `:"a"` apart from `:A` —
    # the two fold to the same string but are different placeholders (#686).
    #
    # If `dedupe` is True (PL/SQL path), keep only the first occurrence of each.
    # Otherwise (plain SQL path) return every occurrence — Oracle expects one
    # bind value per textual occurrence in DML.
    Cleaned = strip_non_bind_text(SQL)
    Seen: list[tuple[str, bool]] = []
    Found: set[tuple[str, bool]] = set()
    for M in _NAMED_BIND_RE.finditer(Cleaned):
        Quoted = M.group(1) is not None
        Entry = (M.group(1), True) if Quoted else (M.group(2).upper(), False)
        if dedupe:
            if Entry not in Found:
                Found.add(Entry)
                Seen.append(Entry)
        else:
            Seen.append(Entry)
    return Seen


def extract_bind_names(SQL: str, dedupe: bool = False) -> list[str]:
    # The placeholder names alone, in SQL order. See `bind_placeholders` for
    # what "name" means for each spelling.
    return [Name for Name, _Quoted in bind_placeholders(SQL, dedupe)]


_RETURNING_RE = re.compile(r'\bRETURNING\b', re.I)
_INTO_RE = re.compile(r'\bINTO\b', re.I)


def returning_bind_positions(SQL: str, num_binds: int) -> frozenset:
    # 0-based positions of the OUT binds in a DML
    # `... RETURNING col[, ...] INTO :b[, ...]` (#120). Empty if the statement
    # isn't a RETURNING-INTO. The INTO binds are the trailing K of the bind
    # list (the leading binds are the VALUES/SET/WHERE inputs); K is the count
    # of placeholders after the RETURNING's INTO, so this is robust to both
    # named and numeric placeholder styles.
    if num_binds <= 0:
        return frozenset()
    Cleaned = strip_non_bind_text(SQL)
    Ret = _RETURNING_RE.search(Cleaned)
    if Ret is None:
        return frozenset()
    Into = _INTO_RE.search(Cleaned, Ret.end())
    if Into is None:
        return frozenset()
    K = len(_ANY_BIND_RE.findall(Cleaned[Into.end() :]))
    if K <= 0 or K > num_binds:
        return frozenset()
    return frozenset(range(num_binds - K, num_binds))


def strip_returning_into(SQL: str) -> str:
    """The same statement with the `INTO :a, :b` of its RETURNING clause removed.

    Oracle spells the clause `RETURNING col[, ...] INTO :bind[, ...]`, naming
    where each returned column goes. Every other database that has the feature
    spells it `RETURNING col[, ...]` and hands the columns back as rows. A Mirror
    backend built on one of those runs the statement without the INTO part and
    reads the rows (#689).

    Returns the statement unchanged when it has no RETURNING-INTO. The INTO list
    ends the statement, so everything from that keyword on is dropped; a trailing
    `;` or whitespace is not part of it and is kept.
    """
    Cleaned = strip_non_bind_text(SQL)
    Ret = _RETURNING_RE.search(Cleaned)
    if Ret is None:
        return SQL
    Into = _INTO_RE.search(Cleaned, Ret.end())
    if Into is None:
        return SQL
    # strip_non_bind_text blanks rather than deletes, so the offset found in the
    # cleaned text indexes the original directly.
    Tail = SQL[Into.end() :]
    Trailing = Tail[len(Tail.rstrip().rstrip(';')) :]
    return SQL[: Into.start()].rstrip() + Trailing
