# Third-party notices

`jevx` application and test source is original Zig code licensed under MIT.
There are no third-party Zig packages.

Release archives bundle the official, unmodified OpenAI Codex CLI package
`rust-v0.156.1`. Codex is Copyright OpenAI and contributors and licensed under
Apache License 2.0. See [`third_party/openai-codex/LICENSE`](third_party/openai-codex/LICENSE)
and [`third_party/openai-codex/NOTICE`](third_party/openai-codex/NOTICE).

The Codex package is kept intact under `vendor/codex/`. Depending on the target,
that upstream package also contains:

- ripgrep 15.2.0 (`codex-path/rg`), dual-licensed under the Unlicense or MIT;
- a portable zsh 5.9-based runtime (`codex-resources/zsh`) on supported Unix
  targets, under the zsh license; and
- native voice components (`codex-resources/voice`) including GStreamer, GLib,
  libffi, PCRE2, Opus, zlib, and related libraries under their respective
  licenses. Windows packages may additionally contain Microsoft's Visual C++
  runtime under Microsoft's terms.

The upstream voice `NOTICE.md`, `licenses/`, `sources.json`, and manifests are
redistributed in place inside the Codex package. They identify exact
platform-specific components, versions, sources, hashes, and license terms.
See the [ripgrep project](https://github.com/BurntSushi/ripgrep), the
[zsh project](https://www.zsh.org/), and the preserved package metadata for
details. Do not extract only `vendor/codex/bin/codex` and discard its sibling
resource, notice, or license directories.

Jev is accessed remotely through the user's OpenRouter account. No Jev model,
OpenRouter credential, TypeSafe SDK, or OpenRouter SDK is included.

Zig 0.16.0 is used as the compiler and standard library. Zig is not bundled in
the release archives.
