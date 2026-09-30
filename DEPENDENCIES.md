# DEPENDENCIES

**This pack uses the Python standard library only.** There is nothing to install: no
`requirements.txt`, no `pyproject.toml`, no lock file, because there is no third-party package to
pin. A test (`tests/test_offline.py`) parses every source file and fails if a module outside the
standard library is imported, or if a dependency file appears.

| Needs | Version | Why |
|---|---|---|
| Python | 3.12 (developed and measured on 3.12.10) | everything |
| git | 2.x on the `PATH` (developed on 2.51) | read-only queries on the generated repositories: `rev-parse`, `diff`, `show-ref`, `cat-file`, `ls-tree`. Never `fetch`, `push`, `clone`, `checkout` or `commit` |

Not needed: a network connection, a container runtime, a compiler, any account.

The generated repositories are written by the pack's own pure-Python git object writer
(`corpus/gitwrite.py`); `git` is only ever asked to read them.

The continuous-integration file (`.github/workflows/ci.yml`) installs nothing. It pins the Python
minor version; the digest of the runner image is `[TO CONFIRM]` at the first remote run (the
workflow has never been executed remotely: nothing was pushed).
