# Contributing to seerdb

Thank you for considering a contribution. Before opening a pull request,
please read this document — seerdb's posture toward the proprietary
protocol it implements imposes some requirements that other open-source
projects don't have.

## Project posture: clean-room reverse-engineering

seerdb is an independent implementation of Oracle's TNS / TTC wire
protocol. The project has no relationship to Oracle Corporation and no
access to Oracle's proprietary protocol specifications. Every byte the
driver sends or decodes was derived from public artifacts and / or from
empirical observation of a running Oracle server that the contributor
was authorized to use.

To keep the project on solid legal footing — both for the maintainers
and for users who ship it — **contributions must follow clean-room
practice.** That means the rules below apply whether you are sending a
1-line typo fix or a 1000-line LOB implementation.

## What you may use as a reference

The following sources are explicitly fine to consult, cite, and derive
work from:

- **python-oracledb source** (Universal Permissive License 1.0 / Apache
  License 2.0). Reading the Cython implementation to understand a
  message layout is fine. Copying code wholesale is not — both
  licenses are permissive but require attribution, and direct copies
  would muddy seerdb's own license. Re-express what you learn in
  your own words / code.
- **cx_Oracle 5.x and earlier** under its old BSD-style license, same
  rules as above.
- **Independent, third-party reimplementations of the protocol** (in any
  language) published under a permissive open-source license (MIT, BSD,
  Apache, and the like). Same rules as above: consult them to understand
  a layout or to corroborate a capture-derived finding, re-express in
  your own code, and attribute any code you do borrow per its license.
  Treat them as a **cross-check against your own packet captures, not a
  primary source** — the wire facts you confirm are what matter, and the
  facts themselves are not copyrightable.
- **Public RFCs, conference talks, blog posts, academic papers,**
  packet-protocol guides, and anything else freely available on the
  web. Cite the URL in your commit message.
- **Wireshark / tcpdump packet captures** of an Oracle server the
  contributor is authorized to use, talking to any client (sqlplus,
  JDBC, sqlcl, oracledb itself). The wire bytes are facts; what they
  represent can be derived empirically.
- **Your own experiments** — sending crafted requests and reading the
  response — against an Oracle instance you have a valid license for.

## What you may NOT use as a reference

- **Oracle source code** (the C / Cython sources of OCI, the server,
  any proprietary client). If you have access to these via an Oracle
  employment, partnership, or NDA, you cannot contribute work derived
  from them. Period.
- **Decompiled or disassembled Oracle binaries.** Reverse-engineering
  against running behavior is fine; reading the binary's internals is
  not.
- **Oracle's documentation text verbatim.** In particular, do not paste
  Oracle's error message catalog — the strings like "ORA-00942: table
  or view does not exist" — into source code or comments as a static
  table. The driver should obtain those strings from the server at
  runtime (the OER block on the wire carries the text), not embed
  them. Brief paraphrases for technical explanation in comments are
  fine; copy-paste of documentation prose is not.
- **Protocol material obtained under an Oracle NDA**, support
  contract, partner program, or any other restricted distribution.
- **Internal Oracle wikis, Slack archives, training material, etc.**
  obtained through privileged channels.

If you are unsure whether something is OK to use, ask before
contributing rather than after.

## In your pull request

- **Cite your sources.** A one-line note in the commit message — e.g.
  "layout cross-referenced with python-oracledb's _process_X" or
  "derived from packet capture of sqlplus 19c against XE 11g" — is
  enough. The point is to leave a paper trail showing the work was
  derived from permissible material.
- **Don't ship Oracle docs prose.** Comments and docstrings should be
  your own description of what the code does and why.
- **Don't ship static error-message tables.** If you need to associate
  numeric ORA codes with PEP 249 exception subclasses or with branching
  behavior, the codes themselves are fine to embed (they're API
  constants); the human-readable strings must come from the server.
- Keep the existing MIT / SPDX header on new source files. The project
  is [REUSE](https://reuse.software/) compliant — see `REUSE.toml`.
- Add tests for new behavior. The offline test suite runs without a
  database; integration tests gated on `PYORACLE_TEST_USER` are the
  right place for anything that needs to talk to a real Oracle.

## Branches and pull-request scope

- **One isolated feature per pull request.** Keep each branch and PR to a
  single, self-contained change — one ticket, one concern. Don't bundle
  separable changes (e.g. several datatypes, or a fix plus an unrelated
  refactor) into one PR; split them so each can be reviewed and reverted on
  its own.
- **Open every PR against `master` — never against another feature branch.**
  Even when a follow-up genuinely builds on an as-yet-unmerged branch, set the
  PR's base to `master`. Branch off the dependency locally for the code if you
  need it, but the PR base stays `master`: until the dependency merges the
  follow-up's diff will also show its commits, and once it merges to `master`
  the diff narrows to just the follow-up. Basing a PR on another feature branch
  invites merging it into that branch by mistake instead of `master`, stranding
  the work off `master`.

## Developer Certificate of Origin

By submitting a pull request, you certify that:

1. The contribution was created in whole or in part by you, and you
   have the right to submit it under the project's MIT license; **or**
   it is based upon previous work that, to the best of your knowledge,
   is covered under an appropriate open-source license that allows you
   to modify it and submit it under the MIT license.
2. The contribution does not contain or derive from any Oracle
   proprietary material as described in the "What you may NOT use"
   section above.
3. The contribution is provided in good faith and you understand and
   agree that the contribution and a record of the contribution
   (including all metadata and the personal information you submit
   with it) is maintained indefinitely and may be redistributed
   consistent with the project's license.

A `Signed-off-by:` trailer in your commit message — easily added with
`git commit -s` — is a convenient way to attest to all three points.

## Not legal advice

This document describes the project's contribution policy and is not
legal advice. If you have any concern about whether you may contribute
specific work, consult a lawyer familiar with software licensing in
your jurisdiction before submitting.
