# jevx

[![CI](https://github.com/SupratimSircar05/jev-zig-cli/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/SupratimSircar05/jev-zig-cli/actions/workflows/ci.yml)
[![Security](https://github.com/SupratimSircar05/jev-zig-cli/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/SupratimSircar05/jev-zig-cli/actions/workflows/security.yml)
[![Pages](https://github.com/SupratimSircar05/jev-zig-cli/actions/workflows/pages.yml/badge.svg?branch=main)](https://github.com/SupratimSircar05/jev-zig-cli/actions/workflows/pages.yml)
[![Release](https://img.shields.io/github/v/release/SupratimSircar05/jev-zig-cli?display_name=tag)](https://github.com/SupratimSircar05/jev-zig-cli/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-2563eb.svg)](LICENSE)

**An auditable terminal agent that combines Codex coding with Jev typed
decisions and deterministic policy enforcement. Built in Zig.**

`jevx` uses the authenticated OpenAI Codex CLI for generative coding work.
TypeSafe's Jev, accessed through OpenRouter, is restricted to bounded
`choice`, `noul`, and `score` decisions for routing, hazard detection, impact
scoring, and verification. Ordinary Zig code—not Jev—owns permissions and
final control flow.

[Website and decision playground](https://supratimsircar05.github.io/jev-zig-cli/)
· [v1.0.0 release](https://github.com/SupratimSircar05/jev-zig-cli/releases/tag/v1.0.0)
· [Architecture](docs/ARCHITECTURE.md)
· [Security policy](SECURITY.md)

> [!IMPORTANT]
> `jevx` is an independent, unofficial community project. It is not endorsed
> by OpenAI, TypeSafe, or OpenRouter. It does not claim better model
> intelligence or desktop-app feature parity. Its measurable focus is
> auditability, deterministic policy, typed decisions, scriptable output,
> crash recovery, and fail-closed dependency handling.

## Quick start

Install on macOS or Linux, including a Linux environment under WSL:

```sh
curl -fsSL https://raw.githubusercontent.com/SupratimSircar05/jev-zig-cli/v1.0.0/install.sh | sh
```

The installer detects the platform, downloads the matching release, verifies
its SHA-256 entry, installs without `sudo`, and starts guided setup when a
terminal is available. Then:

```sh
jevx doctor
jevx -C /path/to/project
```

For a single non-interactive turn, send the prompt through standard input:

```sh
printf '%s\n' 'Review this repository for error-handling gaps.' | \
  jevx run -C /path/to/project
```

Prompts and credentials are never placed in child-process arguments.

## What jevx adds

| Capability | Behavior |
|---|---|
| Typed preflight | Batches action routing, five hazard checks, and impact scoring into one validated Jev request |
| Deterministic policy | Applies tested thresholds and immutable guards in Zig rather than delegating permissions to a model |
| Durable audit | Redacts, encrypts, authenticates, sequences, and hash-chains journal records |
| Safe recovery | Preserves completed history after a truncated final journal frame and forbids unsafe action replay |
| Scriptable operation | Streams versioned JSONL with stable event fields and exit classes |
| Graceful isolation | Keeps Codex authentication, Jev credentials, agent execution, and the browser companion in separate trust boundaries |

The execution path is deliberately small:

```text
prompt on stdin / REPL
        |
        v
redaction -> typed Jev preflight -> deterministic policy gate
                                      | deny / confirm
                                      v
                              durable pre-action audit
                                      |
                                      v
                              Codex exec --json
                                      |
                                      v
                         postflight verification
                         + at most one repair turn
```

See [the architecture notes](docs/ARCHITECTURE.md) for trust boundaries,
degraded operation, browser-bridge isolation, journal design, and replay rules.

## Supported platforms

The v1.0.0 release contains ReleaseSafe builds of both `jevx` and
`jev-decide`, plus the verified official Codex `rust-v0.156.1` package for
each target.

| Platform | Architecture | Release archive | Installation |
|---|---|---|---|
| macOS | Apple silicon (arm64) | `macos-aarch64` | One-line installer or manual |
| macOS | Intel (x86_64) | `macos-x86_64` | One-line installer or manual |
| Linux | arm64, musl | `linux-aarch64` | One-line installer or manual |
| Linux | x86_64, musl | `linux-x86_64` | One-line installer or manual |
| Windows | x86_64 | `windows-x86_64` | Manual archive installation |

Project-owned application, fixture, and test source is Zig 0.16.0 with no
third-party Zig packages. The separately licensed Codex runtime is bundled in
release archives and may be replaced with `--codex-bin`.

## Setup and authentication

```sh
jevx setup
```

Setup checks `codex login status` and opens `codex login` when needed. Codex
owns its ChatGPT OAuth credentials; jevx never reads or copies them.

Jev is configured separately:

- macOS stores the OpenRouter key in Keychain.
- Windows stores it in Credential Manager.
- Linux accepts a session-only `OPENROUTER_API_KEY`.
- Non-secret settings may be imported from
  `~/.config/jev-openrouter/config.json`.

The audit-encryption key is independent of both providers. On Linux, jevx uses
Secret Service when available and otherwise offers an interactive
passphrase-backed fallback.

For a headless or enterprise-managed Codex host, complete device
authentication—or the authentication flow required by your administrator—
before running setup. The bundled Codex runtime is the default and does not
replace an existing system or organization-managed `codex` command. To use an
approved installation instead:

```sh
export JEVX_CODEX_BIN=/approved/path/to/codex
jevx setup
```

You may also pass `--codex-bin /approved/path/to/codex`. Administrators should
validate the selected binary and jevx's deliberately minimal child-process
environment against their proxy, custom-CA, workload-identity, and login
requirements.

For unattended installation, set `JEVX_SKIP_SETUP=1`. Set
`JEVX_INSTALL_DIR` to choose the command directory, or run
`sh install.sh --help` for all supported overrides.

## Command reference

| Command | Purpose |
|---|---|
| `jevx` | Start the streaming interactive REPL |
| `jevx run` | Run one Codex turn; read the prompt from stdin |
| `jevx resume THREAD_ID` | Resume a Codex thread; read the prompt from stdin |
| `jevx decide` | Proxy one typed Jev JSON request from stdin |
| `jevx web` | Start the loopback-only browser decision bridge |
| `jevx doctor` | Check dependencies, authentication, policy, and audit state |
| `jevx policy explain` | Show effective thresholds and immutable guards |
| `jevx audit show` | Decrypt and display redacted audit records |
| `jevx audit verify` | Verify record encryption and chain integrity |
| `jevx audit export` | Export decrypted, redacted JSONL to stdout |
| `jevx audit purge` | Remove the journal after explicit confirmation |
| `jevx setup` | Configure providers, run smoke checks, and initialize the audit key |
| `jevx version` | Print version and pinned toolchain information |

Common options:

```text
--backend exec|app-server
--policy aggressive|balanced|conservative
--model MODEL
--json
-C DIRECTORY
--codex-bin PATH
--jev-bin PATH
--prompt-file PATH
```

The stable default backend is `codex exec --json`. The app-server backend is
preview-only and must be selected explicitly. With pinned Codex `0.156.1`,
jevx rejects app-server before process startup and safely falls back to
`exec`, because that release cannot verifiably ignore inherited user
integrations. The JSONL handshake, streaming, and approval implementation
remains contract-tested for a future pinned Codex release with the required
isolation.

## Policy and failure behavior

The default aggressive profile permits automatic action only when all of these
conditions hold:

- route confidence is at least `0.70`;
- impact is below `1.5` with confidence of at least `0.60`;
- every hazard Noul is below `0.20`; and
- underspecification is below `0.35`.

A project policy may tighten a user policy but cannot relax it. Credential
exfiltration, sandbox bypass, policy tampering, and broad destructive commands
are hard-denied. Pushes, releases, deployments, messages, purchases, account
changes, destructive operations, privilege changes, credential access, and
writes outside the workspace always require confirmation.

If Jev is unavailable, agent turns stop before Codex receives the prompt. This
is intentionally stricter than a read-only fallback: a host read-only sandbox
prevents writes but is not a portable boundary against credential or sensitive
file reads. `doctor`, `audit`, `version`, and `policy explain` remain
available, while `decide` reports the Jev failure directly.

If Codex is unavailable, standalone `decide`, `doctor`, and audit operations
remain available. If a durable pre-action audit write fails, a mutation is
blocked.

## Browser decision playground

The [project website](https://supratimsircar05.github.io/jev-zig-cli/) includes
a clearly labeled deterministic demo. Start `jevx web` to pair it with a
loopback-only live Jev decision bridge:

```sh
jevx web
```

The bridge uses a random per-launch pairing token, accepts typed decisions only,
and cannot execute Codex actions. The static site never receives provider
credentials. Before the configured remote Jev call, jevx redacts the prompt and
enforces policy locally. The bridge does not expose files, audit records,
configuration, or provider credentials over HTTP.

## JSONL and exit classes

`--json` emits JSON Lines containing `schema_version`, monotonic `sequence`,
Unix timestamp, session and turn IDs, event type, and typed data. Stable process
exit classes follow `sysexits` conventions:

| Code | Class |
|---:|---|
| 0 | Success |
| 64 | Usage |
| 69 | Missing dependency |
| 70 | Agent failure |
| 74 | Audit or storage failure |
| 75 | Transient transport |
| 76 | Protocol violation |
| 77 | Authentication |
| 78 | Policy refusal or configuration |

## Verify a release

Download the archive for your platform together with `SHA256SUMS` and
`jevx-v1.0.0.spdx.json` from the
[v1.0.0 release](https://github.com/SupratimSircar05/jev-zig-cli/releases/tag/v1.0.0).
The release also contains a deterministic `jevx-v1.0.0-source.tar.gz`. All six
archives, the SBOM, and the checksum manifest have GitHub provenance
attestations.

```sh
sha256sum --check --ignore-missing SHA256SUMS   # Linux
# macOS: run shasum -a 256 ARCHIVE.tar.gz and compare it with SHA256SUMS
gh attestation verify ARCHIVE.tar.gz --repo SupratimSircar05/jev-zig-cli
tar -xzf ARCHIVE.tar.gz
```

Keep the extracted layout intact: `bin/`, `vendor/codex/`, `third_party/`,
and the notice files must remain siblings. Moving only `bin/jevx` prevents
automatic discovery of the bundled Codex runtime and separates required
notices and resources.

On native Windows, verify and extract the `windows-x86_64` archive with
current Windows `tar` or an equivalent archive tool, then add its `bin`
directory to the user `PATH`.

Release binaries are not Apple-notarized, project-certificate-signed, or
Windows Authenticode-signed. Verify the checksum and provenance attestation
before deciding whether to run an unsigned artifact. Platform signing requires
separately supplied signing credentials.

## Build from source

Use exactly Zig 0.16.0:

```sh
zig version                         # must print 0.16.0
zig fmt --check build.zig src policy
zig build test -Doptimize=ReleaseSafe -j4
zig build -Doptimize=ReleaseSafe -j4
./zig-out/bin/jevx version
```

Installed commands are `jevx` and `jev-decide`.

## Contributing and security

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request. Report vulnerabilities through a
[private GitHub security advisory](https://github.com/SupratimSircar05/jev-zig-cli/security/advisories/new),
not a public issue, and do not include credentials or unredacted audit data.

## License and attribution

Original project source is licensed under the [MIT License](LICENSE). Bundled
Codex artifacts retain their Apache-2.0 license and NOTICE; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Jev is a remote proprietary
service and is not included. The project uses no provider logos and implies no
endorsement.
