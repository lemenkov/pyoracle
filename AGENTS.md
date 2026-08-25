# Notes for coding agents

This file collects repeatable procedures for automated / AI agents working
on seerdb. For the project's clean-room posture and contribution rules, read
[`CONTRIBUTING.md`](CONTRIBUTING.md) first — those requirements always apply.

## Cutting a release

seerdb releases publish to PyPI automatically via GitHub Actions Trusted
Publishing, triggered when the maintainer **pushes a version tag**. An agent's
job is to *prepare* the release on a branch and open the PR — never to merge or
tag it. The steps:

1. **Branch off `master`**, named `release-x.y.z` (e.g. `release-2.3.0`).

2. **Bump the version in both places — they must stay in sync:**
   - `pyproject.toml` → `version = "x.y.z"`
   - `seerdb/common/tns.py` → `_CLIENT_VERSION = 'x.y.z'`

   `_CLIENT_VERSION` is also packed into the `SESSION_CLIENT_VERSION` the driver
   sends on the wire, so a mismatch is a real bug, not just cosmetic.

3. **Update the [`ChangeLog`](ChangeLog):** prepend a new `version x.y.z:` block
   at the top (releases are newest-first; bullets within a release run
   oldest-to-youngest). Each bullet is a short prose line — bold the headline
   phrase and cite the issue/PR as `(#NNN)`. Cover what changed since the last
   tag (`git log <last-tag>..master`), skipping dependabot / pure-CI noise.

4. **Open a PR** against upstream `master` following the normal fork→upstream
   flow (push the branch to your fork, open the PR against `seerdb/seerdb`).
   Title it `Release x.y.z`. In the body, summarise the shipped features and
   state the validation status honestly (which tiers were tested live; call out
   anything validated only against the Mirror / a local bed rather than a real
   server).

5. **Stop there. Do NOT merge the PR, and do NOT create or push the tag.** The
   maintainer reviews, merges, runs a final live-matrix pass, and pushes the
   `x.y.z` tag. Tagging is what publishes to PyPI and creates the GitHub
   release — it is deliberately a human step.

### Versioning

Follow semantic versioning against the **client (DB-API 2.0) surface**, which is
the stable public API. Additive, backward-compatible features are a **minor**
bump; bug fixes are a **patch**. The experimental server-side "Mirror" API is
explicitly *not* covered by semver and may change in any release. A breaking
change to the client API (e.g. the `oracle` → `seerdb` package rename in 2.0.0)
is a **major** bump.
