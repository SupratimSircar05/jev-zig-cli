# Contributing to jevx

Thank you for improving jevx. This project accepts focused issues and pull
requests that preserve its typed-decision boundary, deterministic policy, and
credential isolation.

## Development baseline

- Use exactly Zig 0.16.0 and no third-party Zig packages.
- Keep project-owned executable and test logic in Zig. The repository-root
  `install.sh` and the dependency-free static site are intentional integration
  surfaces.
- Never add credentials, captured prompts, authentication files, decrypted
  journals, or live-tenant data to a fixture or diagnostic.
- Treat Jev as a typed judgment provider, not a permission authority or text
  generator. Ordinary code must keep final control.

Before opening a pull request, run:

```sh
zig fmt --check build.zig src policy
zig build test -Doptimize=ReleaseSafe -j4
zig build -Doptimize=ReleaseSafe -j4
sh -n install.sh
```

Pull requests must pass the hosted CI and security workflows. Changes to
policy, authentication, release packaging, the audit journal, the installer,
or the local browser bridge should include tests and a short threat-boundary
explanation.

## Reviews and security

The protected `main` branch requires a pull request, successful checks, and a
code-owner review. Do not weaken a test or guard to make a change pass. Report
suspected vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
not a public issue.

By contributing, you agree that your contribution is licensed under the
repository's MIT license.
