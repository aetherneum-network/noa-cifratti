# COVERAGE

> A scan that ends `CLEAN` means exactly this: *inside the coverage declared below, nothing was
> found, nothing was left unread and no exception was used.* It does not mean "the system is
> secure". Every report repeats its own scope.

All statements here are about the generated, synthetic repositories of this pack (see
`SYNTHETIC.md`). No coverage of any real-world system is claimed.

## The promise

**Never `CLEAN` on a repository that holds a planted secret of a covered class, in a covered form.**
When the scanner cannot keep that promise on a file, it says `NOT_COVERED` for that file and the
repository can no longer be `CLEAN`.

## Verdicts

Decided by `rules/gate.json`, top to bottom, first match wins:

| Verdict | When | Exit code |
|---|---|---|
| `BLOCKED` | at least one blocking finding (a secret, or a finding of severity high or critical) | 3 |
| `NEEDS_REVIEW` | no blocking finding, at least one suspect: a person has to look | 2 |
| `NOT_COVERED` | nothing found, but something could not be read in full | 2 |
| `EXCEPTIONS_ONLY` | nothing open, but an exception or an exclusion was used | 0 |
| `CLEAN` | every counter at zero | 0 |

Exit code 64 is a usage error or a target that cannot be read at all (a missing directory is an
error, not an empty scan).

## Covered secret classes

A value of these classes is reported when it sits, contiguous and unmodified, in a covered file
(`rules/secrets.json`):

| Class | Covered form |
|---|---|
| `vendor_api_token`, `vendor_test_key`, `vendor_payment_key`, `vendor_webhook_secret` | the token anywhere on a line |
| `armored_key_block` | a begin line, the body and an end line, in order, within 80 lines |
| `connection_uri_password` | a URI that carries a user name and a password before the `@` of the host, the password 6 to 128 characters |
| `assigned_password` | a value of 8 to 128 characters assigned with `=` or `:` to a key whose name contains `password`, `passwd`, `pwd`, `secret`, `token`, `api_key` or `private_key`; quoted in any file, unquoted only in environment-like files (`.env`, `*.env`, `*.yml`, `*.yaml`, `*.ini`, `*.cfg`, `*.conf`, `*.properties`, `*.toml`, `*.sh`, `*.tfvars`) |

Where the scanner looks:

- every file of the working tree, **and its path** (a secret used as a file or folder name is found);
- every blob in the git object database, reachable or not: removed by a later commit, on a branch
  that is not checked out, under a tag, in a commit no ref reaches, in a blob no tree points to;
- the remote URLs of the repository's git configuration;
- for each finding in history: the first commit that introduced it, its author and date, and
  whether it is still in the checked-out tree.

## Suspects (review, not a block and not a pass)

| Class | What it is |
|---|---|
| `encoded_secret` | a covered value found after decoding base64, hexadecimal, percent-encoding, or after reversing the text |
| `concatenated_secret` | a covered value found after joining adjacent string literals with `+` on one line |
| `wordlike_value_under_secret_key` | lowercase words under a secret-looking key: more likely a label than a generated credential, but a weak password looks the same |

## Not covered: the scanner abstains

A file that matches one of these rules (`rules/coverage.json`, ordered) is listed under
`coverage.not_covered` with its path, reason and content hash. It may still be read "best effort",
and a finding in it is still reported, but its silence proves nothing.

| Reason | What |
|---|---|
| `oversized` | larger than 1 MiB (only the prefix is read) |
| `archive_or_encrypted` | zip, gzip, 7z, xz, bzip2, rar, salted or age-encrypted files, armoured messages: not opened |
| `utf16_or_utf32` | text with a UTF-16 or UTF-32 byte order mark |
| `binary` | contains a NUL byte |
| `not_utf8` | not valid UTF-8 |
| `line_too_long` | a line longer than 65,536 characters |
| `lfs_pointer` | a large-file pointer: the content is elsewhere |
| `symlink` | a symbolic link: never followed |
| `nested_repository`, `submodule` | another repository inside: its history is not this scan's |
| `unreadable` | the file could not be opened |
| `history_not_read` | the caller asked for the working tree only and a history exists |
| `history_unreadable`, `shallow_history`, `missing_object` | git is missing, the object database is damaged, or the clone is shallow |
| `config_not_parseable`, `python_not_parseable` | a configuration file in a known schema, or a Python file, that does not parse |

## Configuration and code review

Working tree only (not history), and only these forms:

- **Configuration:** the two invented JSON schemas of this pack (`gateway-routes/v1`, `services/v1`)
  and `KEY=VALUE` environment files. Seven rules (`rules/config.json`): a debug route on the public
  entrypoint, an administration route without forward-auth, a forward-auth that trusts client
  headers, a container-runtime socket mounted in a service, an internal port published on all
  interfaces, a service that bridges the public and the data network, a debug flag enabled.
  Real reverse-proxy, orchestrator or cloud configuration formats are **not** understood.
- **Python code:** seven rules (`rules/pycode.json`) on the syntax tree: dynamic code execution,
  `shell=True`, a shell command, unsafe deserialisation, TLS verification switched off, a debug
  server, a bind on all interfaces. Names are resolved through the file's own import aliases only;
  there is no data-flow analysis. Other languages are not read as code.

These rules are a short working list. No mapping to an external standard (for example the OWASP
lists) is claimed `[TO CONFIRM with legal]`.

## Surface of a patch

`python -m noascan surface BEFORE AFTER` compares the set of exposed items of two trees (public
routes and their flags, published ports on a non-private bind, mounted runtime sockets, debug
flags, covered secrets by fingerprint) with `rules/surface.json`: a patch that grows the surface
is `BLOCKED`; one that swaps items at zero net change is `NEEDS_REVIEW`; a new unreadable file is
`NOT_COVERED`. A bind on `127.`, `10.`, `192.168.` or `::1` counts as private; other private
ranges are treated as public (the stricter reading).

## Known limits

- **Secrets outside the covered forms are missed, and the repository can then be `CLEAN`.** Examples
  measured on the perturbed corpus: a value split across two lines, a value inside a file format the
  generator never used. `eval/history.json` records how many such repositories were called `CLEAN`
  (key `clean_with_only_out_of_coverage_secret`).
- **Quoted values that contain an escaped quote** are not matched by the assignment rule.
- **A password of fewer than 8 characters**, or one assigned to a key with an unrelated name, is not
  reported.
- **Word-like values send clean repositories to review.** A label under a secret-looking key is a
  suspect by rule; on the generated corpora this moves some secret-free repositories from `CLEAN`
  to `NEEDS_REVIEW` (counted in `eval/history.json`, key `clean_repos_not_called_clean`). It is the
  price of never clearing a weak password.
- **The credential rules know only the invented vendors of this pack.** Real provider formats are
  not in the rule file on purpose (see `SYNTHETIC.md`); the generic rules (assignment, URI, key
  block) are the only ones that would fire on other material, and nothing is claimed about that.
- **Configuration and code are reviewed in the working tree only**, not in history.
- **The gold labels, the generator and the scanner have one author.** Agreement between them is
  internal consistency, not independent validation. The blind protocol (`eval/BLIND_PROTOCOL.md`)
  is the first step beyond that, and at the freeze it has not been run.
