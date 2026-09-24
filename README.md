# jevx

`jevx` is an unofficial, auditable terminal agent written in Zig. It uses the
authenticated OpenAI Codex CLI for generative coding work and uses TypeSafe's
Jev, through OpenRouter, only for bounded typed decisions: routing, hazard
detection, impact scoring, and verification.

It does **not** claim better model intelligence or desktop feature parity. Its
measurable advantages are deterministic policy enforcement, typed decisions,
scriptable JSONL, encrypted chained audits, crash recovery, and fail-closed
dependency handling.

## Website

[Learn about jevx and try its decision playground](https://supratimsircar05.github.io/jev-zig-cli/).
The playground uses a clearly labeled deterministic demo by default. Run
`jevx web` to connect it to a loopback-only, live Jev decision bridge; the site
never receives provider credentials and cannot execute Codex actions. The page
uses the ephemeral pairing token printed by `jevx web`, then hands the prompt
and requested policy to the exclusively bound loopback bridge. jevx redacts the
prompt before its configured remote Jev call and enforces policy locally.

## Status

Version 1.0.0. The source requires exactly Zig 0.16.0 and has no third-party Zig
packages. Release archives bundle the official Codex CLI `rust-v0.156.1` under
its Apache-2.0 license; `--codex-bin` may select another installation.

## Build

```sh
zig version                         # must print 0.16.0
zig build test -j4
zig build -Doptimize=ReleaseSafe -j4
./zig-out/bin/jevx doctor
```

Installed commands are `jevx` and `jev-decide`.

## Install

On macOS or Linux, including a Linux environment under WSL:

```sh
curl -fsSL https://raw.githubusercontent.com/SupratimSircar05/jev-zig-cli/v1.0.0/install.sh | sh
```

The installer detects the supported platform, downloads the latest GitHub
release, verifies its SHA-256 entry before extraction, preserves the bundled
Codex and third-party notices, installs without `sudo`, and launches guided
setup when a terminal is available. Set `JEVX_SKIP_SETUP=1` for unattended
installation or `JEVX_INSTALL_DIR` to select the command directory. Run
`sh install.sh --help` for all supported overrides.

The release uses its pinned bundled Codex runtime by default and leaves an
existing system or organization-managed `codex` command untouched. To use a
managed Codex binary instead, export `JEVX_CODEX_BIN=/approved/path/to/codex`
before setup or pass `--codex-bin /approved/path/to/codex`. jevx delegates login
and credential ownership to the selected Codex binary and never copies its
credentials. Enterprise administrators should validate the selected binary and
jevx's deliberately minimal child-process environment against their required
proxy, custom-CA, workload-identity, and login controls before deployment.

### Manual verification

Download the archive matching your platform from the GitHub release, plus
`SHA256SUMS` and `jevx-v1.0.0.spdx.json`. The release also publishes the
deterministic `jevx-v1.0.0-source.tar.gz` source archive. All six archives, the
SBOM, and the checksum manifest receive GitHub provenance attestations. Verify
the selected archive before extracting it:

```sh
sha256sum --check --ignore-missing SHA256SUMS   # Linux
# macOS: shasum -a 256 ARCHIVE.tar.gz and compare with SHA256SUMS
gh attestation verify ARCHIVE.tar.gz --repo SupratimSircar05/jev-zig-cli
tar -xzf ARCHIVE.tar.gz
```

Keep the extracted directory layout intact. In particular, `bin/`,
`vendor/codex/`, `third_party/`, and the notice files must remain siblings;
moving only `bin/jevx` prevents automatic discovery of the bundled Codex
runtime and separates its required notices/resources. Add the extracted
`bin` directory to `PATH`, for example:

```sh
export PATH="$PWD/jevx-v1.0.0-linux-x86_64/bin:$PATH"
jevx setup
```

On native Windows, download the `windows-x86_64` archive and `SHA256SUMS`,
verify the digest, extract with current Windows `tar` (or an equivalent archive
tool), then add the extracted `bin` directory to the user `PATH`. The binaries
are not Apple-notarized or code-signed with a project certificate, and the
Windows executable is not Authenticode-signed. Verify the checksum and GitHub
provenance attestation before deciding whether to run an unsigned artifact.
Platform signing can be added only when separate signing credentials are
supplied.

## First run

```sh
jevx setup
```

Setup checks `codex login status` and opens `codex login` if necessary. Codex
owns its OAuth credentials. Jev configuration is separate: macOS uses Keychain,
Windows uses Credential Manager, and Linux requires a session-only
`OPENROUTER_API_KEY`. Non-secret Jev configuration may be imported from
`~/.config/jev-openrouter/config.json`. The audit-encryption key is a different
secret: Linux stores it with Secret Service when available and otherwise offers
an interactive passphrase-backed fallback.

For a headless Codex host, complete Codex device authentication or the managed
enterprise authentication configured by your administrator before running
`jevx setup`. The installer never places ChatGPT, Codex, OpenAI, or OpenRouter
credentials in command arguments.

## Commands

```text
jevx                         streaming REPL
jevx run                     one turn; prompt is read from stdin
jevx resume THREAD_ID        resume a Codex thread; prompt is read from stdin
jevx decide                  proxy one typed Jev JSON request from stdin
jevx web                     local browser bridge for typed decisions only
jevx doctor                  dependency, auth, policy, and audit diagnostics
jevx policy explain          print effective thresholds and immutable guards
jevx audit show              decrypt and display redacted records
jevx audit verify            verify AEAD frames and chain integrity
jevx audit export            export decrypted, redacted JSONL to stdout
jevx audit purge             explicitly remove the journal after confirmation
jevx setup                   first-run configuration and smoke checks
jevx version
```

Common options are `--backend exec|app-server`,
`--policy aggressive|balanced|conservative`, `--model`, `--json`, `-C`,
`--codex-bin`, and `--jev-bin`. Prompts are never forwarded in a child-process
argument. The default backend is stable `codex exec --json`. The app-server
protocol backend is preview-only and must be selected explicitly. With pinned
Codex `0.156.1`, `jevx` rejects it before process startup and falls back to
`exec`, because that app-server version cannot verifiably ignore inherited
user integrations. Its JSONL handshake, streaming, and approval protocol remain
contract-tested for a future pinned Codex version that supplies this isolation.

## Policy

One batched Jev preflight asks for an action Choice, five hazard Nouls, and an
impact Score. The default aggressive profile can act automatically only when:

- route confidence is at least `0.70`;
- impact is below `1.5` and impact confidence is at least `0.60`;
- every hazard Noul is below `0.20`; and
- underspecification is below `0.35`.

Ordinary Zig code—not Jev—makes the final permission decision. A project policy
may tighten a user policy but cannot relax it. See [the security policy](SECURITY.md)
and [architecture notes](docs/ARCHITECTURE.md).

If Jev is unavailable, agent turns fail closed before Codex receives the
prompt. This is deliberately stricter than a read-only fallback: Codex's host
read-only sandbox prevents writes but does not provide a portable guarantee
that sensitive files or OS credential services cannot be read. Standalone
`doctor`, `audit`, `version`, and `policy explain` remain usable; `decide`
reports the Jev failure directly.

## Machine output and exit classes

`--json` emits JSON Lines with `schema_version`, monotonic `sequence`, Unix
timestamp, session and turn IDs, event type, and typed data. Stable process exit
classes follow `sysexits` conventions:

| Code | Class |
|---:|---|
| 0 | success |
| 64 | usage |
| 69 | missing dependency |
| 70 | agent failure |
| 74 | audit/storage failure |
| 75 | transient transport |
| 76 | protocol violation |
| 77 | authentication |
| 78 | policy refusal/configuration |

## Licensing

Original project source is MIT licensed. Bundled Codex artifacts retain their
Apache-2.0 license and NOTICE. Jev is a remote proprietary service and is not
included. This repository uses no provider logos and implies no endorsement.
