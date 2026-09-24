## What changed

Describe the bounded change and why it is needed.

## Trust-boundary impact

- [ ] No authentication, policy, audit, installer, release, or browser-bridge impact
- [ ] Trust-boundary impact is explained below

## Verification

- [ ] `zig fmt --check build.zig src policy`
- [ ] `zig build test -Doptimize=ReleaseSafe -j4`
- [ ] `zig build -Doptimize=ReleaseSafe -j4`
- [ ] Relevant failure and recovery paths were exercised

## Security hygiene

- [ ] No credentials, private prompts, decrypted journals, or live-tenant data were added
- [ ] New dependencies or external actions are pinned and justified
