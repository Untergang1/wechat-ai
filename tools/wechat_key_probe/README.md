# Independent SQLCipher diagnostic tools

This directory contains experimental diagnostics, separate from the production
scanner and database service. It does not change their interfaces or SQLCipher
parameters. Run commands from the repository root.

## Synthetic database verification

The standalone verifier has no process inspection or key-discovery capability.
Its self-test creates a temporary database with public fixture material, checks
correct and incorrect inputs, and deletes the fixture when finished:

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,src="$PWD/tools/wechat_key_probe",dst=/probe-tool,readonly \
  --entrypoint /opt/venv-bot/bin/python wechat-ai:latest \
  /probe-tool/verify_database.py --self-test
```

This uses the existing image's SQLCipher driver. It does not mount account data,
share host process namespaces, or require additional Linux capabilities. The
wrong-key test may emit expected SQLCipher HMAC errors on stderr; its JSON result
indicates whether that rejection was expected and successful.

For an already supplied disposable database copy, the verifier accepts a JSON
object on stdin with `key`: 96 hexadecimal characters representing a 32-byte raw
key and 16-byte salt. Its default database path is `/probe/data.db`. Do not supply
an original account directory. The copy can create its own SQLite sidecar files.
Use a private pipe, not a command-line argument, for this input. Docker must use
`-i` to forward stdin. No key export is provided.

The result contains `opened`, `quick_check_ok`, and, on failure, `stage` and
`error_type`. Stages distinguish input parsing, missing copies, driver loading,
opening, schema access, and integrity checks. Exception messages, keys and data
rows are not included. Exit status is 0 for a successful check and 2 for a failed
check. No cipher defaults are overridden.

## Experimental process diagnostics

`probe.py` exposes `inspect`, `capture-live`, and `capture-startup`, with
`--container` (default `wechat-ai`), `--timeout` (default 120 seconds), and
`--max-hits` (default 200). The latter two modes affect the target process and
are distinct from the synthetic verification workflow above.

The current profile supports only the x86-64 executable with Build ID
`d16278a416e000526fd22aec59973e54f91291e4`, observed in WeChat 4.1.13.9.
ELF segments, ASLR load bias, file bytes and live instruction bytes are checked
before installing breakpoints. Unknown builds are rejected. There is no
whole-memory scan, regular-expression fallback, or parameter search.

When invoked as a non-root host user, the diagnostic controller uses a temporary
container to run host GDB. That container shares the host PID namespace, has
`SYS_PTRACE`, and disables its seccomp and AppArmor restrictions. The host root
is mounted read-only, with a private temporary output directory writable. This
is a privileged diagnostic environment; a read-only root mount is not a complete
security boundary, particularly because the Docker socket remains accessible.
The tool does not change the application's image or Docker configuration.

Capture uses temporary software breakpoints and briefly stops threads. Normal
timeout and handled interruption delete breakpoints and detach. Force-killing
the debugger, host failures and unhandled cleanup failures are not covered by
that guarantee. The result records debugger cleanup events and `TracerPid`.
Output includes progress lines followed by redacted JSON; do not treat the
entire stdout stream as a single JSON document.

Captured material stays in controller/debugger memory and their private pipe
unless the explicit `--write-key-file` option is used.
Only validated page keys are considered for copy verification. Copy verification
temporarily pauses discovered writable DB/WAL owners, copies DB and WAL without
SHM, then resumes them. A five-second watchdog bounds normal snapshot pauses.
Every captured core database (contacts and numbered message shards) is copy
verified, in addition to the first available candidate. Explicit core targets
are not skipped based on file size; snapshot pauses and verification timeouts
bound the operation. Temporary copies are deleted on normal completion.

`--write-key-file /config/database_keys.json` explicitly persists copy-verified
entries in the target container, through a private stdin pipe and the project's
`linux_key_file` writer. The running container must contain that module. Existing
valid entries are retained; writes use an atomic replacement with mode `0600`.
`--database-root` defaults to `/config/xwechat_files` and defines relative paths
in the file. No key value is printed. This changes the default in-memory-only
retention policy only when requested explicitly.

`core_unverified` reports missing core checks separately from `success` (at
least one complete verification). Production readiness must also be checked
through the service's `core_ready` and actual API/polling results.

`capture-startup` additionally attempts one graceful application replacement,
preserves its launch environment and account files, and temporarily stops the
bot supervisor to avoid competing launches. It waits up to ten minutes for
business-database activity. It cannot detect or complete QR/phone approval: the
operator must monitor the desktop. **This startup workflow has not been tested
against the actual application and is not required by the current findings.**

## Validation and current status

Run the non-attaching unit tests:

```sh
python3 -m unittest discover -s tests -p test_wechat_key_probe.py -v
```

Two additional opt-in tests use GDB only on disposable compiled fixture children
when `WECHAT_PROBE_GDB_TEST=1` is set. They exercise concurrent KDF return pairing,
invalid buffers, redacted output, and timeout detach. They require `cc` and GDB.

Evidence collected during this task:

- A previous live observation reached the cipher boundary 200 times, produced
  four unique candidate keys, and validated the page-1 HMACs of `session.db`,
  `contact.db`, `message_0.db`, and `message_fts.db`. Detach reported `TracerPid=0`.
- The subsequent copy check failed at the tooling layer. Inspection found that
  its Docker invocation did not forward stdin. This invocation now uses `-i`;
  failures preserve their stage instead of collapsing into a generic error.
- Synthetic SQLCipher validation passes for correct input, rejects wrong input,
  identifies missing/malformed stdin, and leaves the fixture DB unchanged.
- A subsequent authorized recovery run verified copies of `contact.db` and
  `message_0.db`, in addition to `session.db` and `hardlink.db`, and persisted only
  the four verified credentials. No cipher-parameter change or WeChat restart
  was needed. Production integration uses the credential file; it does not run
  this debugger automatically. See the linked service recovery documentation.

Generated reports, credentials, database copies and binaries must not be
version-controlled. Runtime credentials use the ignored `/config` volume;
temporary diagnostic artifacts belong outside the working tree. File-based
production recovery is documented in [database credentials](../../docs/database-credentials.md).
