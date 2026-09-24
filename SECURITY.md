# Security policy

## Supported versions

Security fixes target the latest tagged `1.x` release and the `main` branch.
Older release lines may receive a fix only when the same change can be applied
safely; otherwise users should upgrade to the current release.

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

## What to report

Please report authentication or authorization bypasses, credential disclosure,
policy or sandbox bypasses, audit-integrity failures, unsafe installer behavior,
memory-safety defects, and vulnerabilities in the local browser bridge. Ordinary
support questions and expected policy refusals are not security vulnerabilities.

## Private reporting

Use a [private GitHub security advisory](https://github.com/SupratimSircar05/jev-zig-cli/security/advisories/new).
Do not open a public issue for a suspected vulnerability. Do not include working
API keys, OAuth material, unredacted audit journals, private prompts, or data that
belongs to another person in a report. A minimal, redacted reproducer is ideal.

## Disclosure process

The maintainer aims to acknowledge a vulnerability report within 3 business
days, provide an initial triage result within 7 days, and coordinate a fix and
disclosure within 90 days. Severity, dependency coordination, or a release-signing
constraint can change that timeline; the reporter will receive an update when it
does. Please allow the coordinated disclosure window to complete before publishing
technical details.

Good-faith research that avoids privacy violations, service disruption, social
engineering, and access beyond the reporter's own accounts is welcome. Stop and
report promptly if testing exposes credentials or private data.
