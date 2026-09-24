# Architecture

## Trust boundary

`jevx` owns deterministic control flow, permission decisions, durable audit
writes, redaction, replay prevention, process isolation, and exit mapping.
Codex owns generative coding and its ChatGPT OAuth session. Jev supplies only
closed-output semantic judgments.

```text
prompt on stdin / REPL
        |
        v
redact -> typed Jev preflight -> deterministic policy gate
                                 | deny/confirm
                                 v
                         durable pre-action audit
                                 |
                    +------------+-------------+
                    |                          |
             codex exec --json         app-server preview
                    |                          |
                    +------- streamed events--+
                                 |
                        one postflight check
                                 |
                      optional one repair turn
```

## Replay rule

If app-server fails before a turn starts, `jevx` may fall back to the exec
backend. Once a command/file action has begun, automatic replay is forbidden;
the result is reported for explicit operator recovery.

Pinned Codex `0.156.1` cannot verifiably ignore inherited user integrations in
app-server mode. The production build therefore rejects that backend before
spawning it and takes the safe pre-turn fallback; the protocol implementation
is retained under contract tests for a future isolated release.

## Degraded operation

- Without Jev, agent turns fail closed before Codex sees the prompt. Host
  read-only sandboxes prevent writes but do not portably confine reads away
  from credentials; pretending an unclassified request is safe would violate
  the immutable exfiltration guard. Diagnostics and audit operations continue.
- Without Codex, `decide`, `doctor`, and audit operations remain available.
- If a durable pre-action journal write fails, mutation is blocked.

## Journal

Each length-delimited record is redacted, encrypted independently with
XChaCha20-Poly1305, authenticates session/sequence metadata, and includes the
previous record hash. Verification detects corruption and reordering within
the history that is present. A clean removal of complete trailing frames
requires an independently stored tail anchor and is not claimed here. An
incomplete final frame is ignored/repaired; earlier valid frames are kept.
Records are never pruned automatically.

## Jev adapters

The alpha Decisions endpoint and `/api/v1/systemone` are explicit adapters.
They never silently fail over. Request and response validators enforce bounded
sizes, the three supported question types, Choice and Score limits, finite
values, and tolerant optional metadata.

## Browser companion

The GitHub Pages site is static and contains no provider credential. Its
playground is an explicitly labeled deterministic demo unless a user starts
`jevx web` locally. The bridge binds exclusively to IPv4 loopback, preferring
`127.0.0.1:4768` and falling back to an ephemeral port for safe restart. It validates the
`Host` header, restricts CORS to the project Pages origin and loopback
development origins, requires a random per-launch pairing token, rejects
chunked or oversized requests, and returns typed preflight decisions only. It
does not expose Codex execution, files, audit records, configuration, or
provider credentials over HTTP. A real Jev call still runs inside the local
`jevx` process through the normal credential and validation path, after local
redaction; the exact workspace path is withheld from the provider.
