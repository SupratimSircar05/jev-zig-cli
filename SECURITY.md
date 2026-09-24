# Security policy

## Supported version

Security fixes target the latest tagged release. Until 1.0, configuration and
file formats may change with an explicit migration note.

## Credential handling

- Codex owns its ChatGPT OAuth session. `jevx` invokes `codex login` and never
  reads, copies, or exports Codex tokens.
- The OpenRouter API key is resolved at runtime. It must never be passed in an
  argument, written to configuration, included in an audit record, or emitted
  in diagnostics.
- Audit plaintext is redacted before it reaches the encrypted journal.
- `--dangerously-bypass-approvals-and-sandbox` and equivalent modes are never
  generated or accepted.

## Immutable guards

Credential exfiltration, sandbox bypass, policy tampering, and broad destructive
commands are denied in code. Pushes, releases, deployments, messages, purchases,
account changes, destructive actions, privilege changes, credential access, and
writes outside the selected workspace require a human confirmation.

Jev is mandatory for an agent turn. If its typed preflight cannot be obtained,
`jevx` fails closed before invoking Codex. A host `read-only` sandbox is not
treated as a credential-read boundary.

## Reporting

Please open a private GitHub security advisory. Do not include working API keys,
OAuth material, unredacted audit journals, or private prompts in a report.
