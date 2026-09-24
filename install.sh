#!/bin/sh
# Install a checksum-verified jevx release without root privileges.
#
# The public entrypoint is intentionally POSIX sh compatible:
#   curl -fsSL https://raw.githubusercontent.com/SupratimSircar05/jev-zig-cli/v1.0.0/install.sh | sh

set -eu
set -f

PROGRAM=jevx-installer
REPOSITORY=SupratimSircar05/jev-zig-cli
REPOSITORY_URL=https://github.com/$REPOSITORY
CODEX_INSTALL_URL=https://chatgpt.com/codex/install.sh

say() {
    printf '%s\n' "$*"
}

note() {
    printf '%s: %s\n' "$PROGRAM" "$*" >&2
}

die() {
    note "error: $*"
    exit 1
}

usage() {
    cat <<'EOF'
Install the latest checksum-verified jevx release for macOS or Linux.

Usage:
  sh install.sh
  sh install.sh --help
  curl -fsSL https://raw.githubusercontent.com/SupratimSircar05/jev-zig-cli/v1.0.0/install.sh | sh

Environment:
  JEVX_VERSION=v1.0.0       Install this exact release (default: latest).
  JEVX_INSTALL_DIR=PATH     Command directory (default: $HOME/.local/bin).
  JEVX_SKIP_SETUP=1         Do not run the interactive `jevx setup` wizard.
  JEVX_SKIP_CODEX=1         Do not offer optional system Codex installation.
  JEVX_CODEX_BIN=PATH       Select a managed Codex binary for guided setup.

The release includes the pinned official Codex runtime used by default. If a
separate `codex` command is already installed (including an organization-
managed installation), this installer leaves it and its authentication alone.
Export JEVX_CODEX_BIN before installation to select that approved binary for
the guided setup invocation.

For Windows, download and verify the native windows-x86_64 archive from:
  https://github.com/SupratimSircar05/jev-zig-cli/releases/latest
EOF
}

case ${1-} in
    '') ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        die "unknown argument: $1"
        ;;
esac

if [ "$#" -gt 1 ]; then
    usage >&2
    die "too many arguments"
fi

validate_switch() {
    switch_name=$1
    switch_value=$2
    case $switch_value in
        ''|0|1) ;;
        *) die "$switch_name must be 0 or 1" ;;
    esac
}

validate_switch JEVX_SKIP_SETUP "${JEVX_SKIP_SETUP-}"
validate_switch JEVX_SKIP_CODEX "${JEVX_SKIP_CODEX-}"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v mktemp >/dev/null 2>&1 || die "mktemp is required"
command -v diff >/dev/null 2>&1 || die "diff is required"
command -v readlink >/dev/null 2>&1 || die "readlink is required"

if command -v sha256sum >/dev/null 2>&1; then
    SHA_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    SHA_TOOL=shasum
else
    die "sha256sum (Linux) or shasum (macOS) is required"
fi

os_raw=$(uname -s 2>/dev/null) || die "could not identify the operating system"
case $os_raw in
    Darwin) platform_os=macos ;;
    Linux) platform_os=linux ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        die "native Windows installation uses the windows-x86_64 release; download it from $REPOSITORY_URL/releases/latest"
        ;;
    *) die "unsupported operating system: $os_raw (supported: macOS and Linux; Windows has a native release)" ;;
esac

arch_raw=$(uname -m 2>/dev/null) || die "could not identify the CPU architecture"
case $arch_raw in
    x86_64|amd64) platform_arch=x86_64 ;;
    arm64|aarch64) platform_arch=aarch64 ;;
    *) die "unsupported CPU architecture: $arch_raw (supported: x86_64 and aarch64)" ;;
esac

platform=$platform_os-$platform_arch

download() {
    download_url=$1
    download_destination=$2
    curl -fsSL \
        --proto '=https' \
        --proto-redir '=https' \
        -o "$download_destination" \
        "$download_url"
}

resolve_latest_version() {
    latest_url=$(curl -fsSL \
        --proto '=https' \
        --proto-redir '=https' \
        -o /dev/null \
        -w '%{url_effective}' \
        "$REPOSITORY_URL/releases/latest") || return 1
    case $latest_url in
        "$REPOSITORY_URL"/releases/tag/*)
            printf '%s\n' "${latest_url##*/}"
            ;;
        *)
            return 1
            ;;
    esac
}

validate_version() {
    candidate=$1
    case $candidate in
        v*) version_numbers=${candidate#v} ;;
        *) return 1 ;;
    esac

    old_ifs=$IFS
    IFS=.
    # Intentional field splitting validates the three numeric components.
    # shellcheck disable=SC2086
    set -- $version_numbers
    IFS=$old_ifs
    [ "$#" -eq 3 ] || return 1
    [ "v$1.$2.$3" = "$candidate" ] || return 1
    for component in "$@"; do
        case $component in
            ''|*[!0-9]*) return 1 ;;
        esac
    done
    return 0
}

if [ -n "${JEVX_VERSION-}" ]; then
    case $JEVX_VERSION in
        v*) version=$JEVX_VERSION ;;
        *) version=v$JEVX_VERSION ;;
    esac
else
    note "resolving the latest release"
    version=$(resolve_latest_version) || die "could not resolve the latest GitHub release; set JEVX_VERSION to retry an exact version"
fi
validate_version "$version" || die "invalid release version: $version (expected vMAJOR.MINOR.PATCH)"

if [ -n "${JEVX_INSTALL_DIR-}" ]; then
    install_dir=$JEVX_INSTALL_DIR
else
    [ -n "${HOME-}" ] || die "HOME is unset; set JEVX_INSTALL_DIR explicitly"
    install_dir=$HOME/.local/bin
fi
[ -n "$install_dir" ] || die "JEVX_INSTALL_DIR must not be empty"

case $install_dir in
    /*) ;;
    *)
        working_dir=$(pwd -P) || die "could not resolve the current directory"
        install_dir=$working_dir/$install_dir
        ;;
esac

umask 077
mkdir -p "$install_dir" || die "cannot create install directory: $install_dir"
install_dir=$(CDPATH='' cd "$install_dir" && pwd -P) || die "cannot resolve install directory: $install_dir"

state_dir=$install_dir/.jevx
releases_dir=$state_dir/releases
if [ -L "$state_dir" ]; then
    die "refusing symlinked installer state directory: $state_dir"
fi
mkdir -p "$releases_dir" || die "cannot create release directory: $releases_dir"
if [ -L "$releases_dir" ]; then
    die "refusing symlinked release directory: $releases_dir"
fi

temp_dir=$(mktemp -d "$state_dir/install.XXXXXX") || die "could not create a secure temporary directory"
case $temp_dir in
    "$state_dir"/install.*) ;;
    *) die "temporary directory was created outside installer state" ;;
esac
created_jevx_link=0
created_decide_link=0
release_created=0
release_dir=
next_link=
current_link=
lock_dir=$state_dir/install.lock
lock_held=0
activated=0

cleanup() {
    cleanup_status=$?
    # The activation rename is atomic, but a signal may arrive after `mv`
    # commits and before the next shell assignment. Re-read the link before
    # deciding whether the newly activated release is safe to remove.
    if [ "$activated" -ne 1 ] && [ -n "${current_link-}" ] && [ -n "${release_id-}" ] && [ -L "$current_link" ]; then
        cleanup_target=$(readlink "$current_link" 2>/dev/null || :)
        if [ "$cleanup_target" = "releases/$release_id" ]; then
            activated=1
        fi
    fi
    if [ "$activated" -ne 1 ]; then
        if [ "$created_jevx_link" -eq 1 ]; then
            rm -f "$install_dir/jevx" 2>/dev/null || :
        fi
        if [ "$created_decide_link" -eq 1 ]; then
            rm -f "$install_dir/jev-decide" 2>/dev/null || :
        fi
        if [ -n "$release_dir" ] && [ "$release_created" -eq 1 ]; then
            rm -rf "$release_dir" 2>/dev/null || :
        fi
    fi
    if [ -n "$next_link" ]; then
        rm -f "$next_link" 2>/dev/null || :
    fi
    if [ "$lock_held" -eq 1 ]; then
        rmdir "$lock_dir" 2>/dev/null || :
    fi
    rm -rf "$temp_dir" 2>/dev/null || :
    exit "$cleanup_status"
}
trap cleanup 0
trap 'exit 130' HUP INT TERM

if ! mkdir "$lock_dir" 2>/dev/null; then
    die "another installation is running, or a stale lock remains at $lock_dir"
fi
lock_held=1

archive_name=jevx-$version-$platform.tar.gz
archive_root=jevx-$version-$platform
archive_path=$temp_dir/$archive_name
checksums_path=$temp_dir/SHA256SUMS
release_base=$REPOSITORY_URL/releases/download/$version

note "downloading $archive_name"
download "$release_base/SHA256SUMS" "$checksums_path" || die "could not download SHA256SUMS for $version"
download "$release_base/$archive_name" "$archive_path" || die "could not download $archive_name"

expected_checksum=
checksum_matches=0
checksum=
filename=
remainder=
while IFS=' ' read -r checksum filename remainder || [ -n "$checksum$filename$remainder" ]; do
    filename=${filename#\*}
    if [ "$filename" = "$archive_name" ]; then
        checksum_matches=$((checksum_matches + 1))
        expected_checksum=$checksum
    fi
done < "$checksums_path"

[ "$checksum_matches" -eq 1 ] || die "SHA256SUMS must contain exactly one entry for $archive_name"
[ "${#expected_checksum}" -eq 64 ] || die "invalid SHA-256 entry for $archive_name"
case $expected_checksum in
    *[!0-9a-f]*) die "invalid SHA-256 entry for $archive_name" ;;
esac

if [ "$SHA_TOOL" = sha256sum ]; then
    checksum_output=$(sha256sum "$archive_path") || die "could not hash $archive_name"
else
    checksum_output=$(shasum -a 256 "$archive_path") || die "could not hash $archive_name"
fi
# Intentional field splitting selects the digest at the beginning of the
# checksum tool's ordinary output. Globbing is disabled for the whole script.
# shellcheck disable=SC2086
set -- $checksum_output
actual_checksum=${1-}
[ "$actual_checksum" = "$expected_checksum" ] || die "checksum verification failed for $archive_name"
note "verified SHA-256: $expected_checksum"

archive_listing=$temp_dir/archive.list
tar -tzf "$archive_path" > "$archive_listing" || die "could not inspect $archive_name"
archive_manifest=$temp_dir/archive.manifest
tar -tvzf "$archive_path" > "$archive_manifest" || die "could not inspect archive entry types"
manifest_line=
while IFS= read -r manifest_line || [ -n "$manifest_line" ]; do
    entry_type=${manifest_line%"${manifest_line#?}"}
    case $entry_type in
        -|d) ;;
        *) die "release archive contains a link or special file" ;;
    esac
done < "$archive_manifest"
listing_entries=0
entry=
while IFS= read -r entry || [ -n "$entry" ]; do
    listing_entries=$((listing_entries + 1))
    [ "$listing_entries" -le 10000 ] || die "release archive contains too many entries"
    case $entry in
        "$archive_root"|"$archive_root/"*) ;;
        *) die "release archive contains an unexpected path: $entry" ;;
    esac
    case /$entry/ in
        */../*|*/./*) die "release archive contains an unsafe path: $entry" ;;
    esac
done < "$archive_listing"
[ "$listing_entries" -gt 0 ] || die "release archive is empty"

extract_dir=$temp_dir/extracted
mkdir "$extract_dir" || die "could not create extraction directory"
tar -xzf "$archive_path" -C "$extract_dir" || die "could not extract $archive_name"
extracted_root=$extract_dir/$archive_root
if [ ! -d "$extracted_root" ] || [ -L "$extracted_root" ]; then
    die "release root is not a regular directory"
fi

for executable in jevx jev-decide; do
    executable_path=$extracted_root/bin/$executable
    [ -f "$executable_path" ] || die "release is missing bin/$executable"
    [ ! -L "$executable_path" ] || die "release bin/$executable must not be a symbolic link"
    chmod u+x "$executable_path" || die "could not mark bin/$executable executable"
done
if [ ! -d "$extracted_root/vendor/codex" ] || [ -L "$extracted_root/vendor/codex" ]; then
    die "release is missing the bundled Codex runtime"
fi
if [ ! -x "$extracted_root/vendor/codex/bin/codex" ] || [ -L "$extracted_root/vendor/codex/bin/codex" ]; then
    die "release is missing the bundled Codex executable"
fi
[ -f "$extracted_root/LICENSE" ] || die "release is missing LICENSE"
[ -f "$extracted_root/THIRD_PARTY_NOTICES.md" ] || die "release is missing THIRD_PARTY_NOTICES.md"

release_id=$version-$platform-$expected_checksum
release_dir=$releases_dir/$release_id
if [ -e "$release_dir" ] || [ -L "$release_dir" ]; then
    if [ ! -d "$release_dir" ] || [ -L "$release_dir" ]; then
        die "existing release path is not a directory: $release_dir"
    fi
    if find "$release_dir" ! -type d ! -type f -print -quit | grep -q .; then
        die "existing release contains a link or special file: $release_dir"
    fi
    if find "$release_dir" -type f -links +1 -print -quit | grep -q .; then
        die "existing release contains a hard-linked file: $release_dir"
    fi
    if ! diff -r "$extracted_root" "$release_dir" >/dev/null 2>&1; then
        die "existing checksum-named release differs from the verified archive: $release_dir"
    fi
    [ -x "$release_dir/bin/jevx" ] || die "existing release is incomplete: $release_dir"
    [ -x "$release_dir/bin/jev-decide" ] || die "existing release is incomplete: $release_dir"
    [ -x "$release_dir/vendor/codex/bin/codex" ] || die "existing release is missing its bundled Codex runtime: $release_dir"
    note "checksum-matched release is already staged"
else
    mv "$extracted_root" "$release_dir" || die "could not stage the verified release"
    release_created=1
fi

validate_command_slot() {
    command_path=$1
    expected_target=$2
    if [ -L "$command_path" ]; then
        current_target=$(readlink "$command_path") || die "could not inspect $command_path"
        [ "$current_target" = "$expected_target" ] || die "refusing to overwrite unrelated symbolic link: $command_path"
    elif [ -e "$command_path" ]; then
        die "refusing to overwrite existing file: $command_path"
    fi
}

jevx_target=.jevx/current/bin/jevx
decide_target=.jevx/current/bin/jev-decide
validate_command_slot "$install_dir/jevx" "$jevx_target"
validate_command_slot "$install_dir/jev-decide" "$decide_target"

if [ ! -L "$install_dir/jevx" ]; then
    ln -s "$jevx_target" "$install_dir/jevx" || die "could not create jevx command link"
    created_jevx_link=1
fi
if [ ! -L "$install_dir/jev-decide" ]; then
    ln -s "$decide_target" "$install_dir/jev-decide" || die "could not create jev-decide command link"
    created_decide_link=1
fi

current_link=$state_dir/current
if [ -e "$current_link" ] && [ ! -L "$current_link" ]; then
    die "refusing to overwrite non-link activation path: $current_link"
fi
next_link=$state_dir/current.new.$$
rm -f "$next_link"
ln -s "releases/$release_id" "$next_link" || die "could not prepare release activation"
if [ "$platform_os" = linux ]; then
    # GNU and BusyBox mv otherwise treat a link to a directory as the target
    # directory. -T makes this an atomic link-for-link replacement.
    mv -fT "$next_link" "$current_link" || die "could not activate release"
else
    # BSD mv follows a destination link to a directory unless -h is used.
    mv -fh "$next_link" "$current_link" || die "could not activate release"
fi
activated=1

say "Installed jevx $version for $platform in $install_dir"

case :${PATH-}: in
    *:"$install_dir":*) ;;
    *)
        say "Add this directory to PATH:"
        say "  export PATH=\"$install_dir:\$PATH\""
        ;;
esac

interactive=0
if ( : </dev/tty ) 2>/dev/null && ( : >/dev/tty ) 2>/dev/null; then
    interactive=1
fi

if command -v codex >/dev/null 2>&1; then
    note "existing Codex command detected and left untouched; jevx uses its bundled runtime unless JEVX_CODEX_BIN selects the managed binary"
elif [ "${JEVX_SKIP_CODEX-0}" = 1 ]; then
    note "system Codex installation skipped; jevx will use its checksum-matched bundled runtime"
elif [ "$interactive" -eq 1 ]; then
    {
        printf '%s\n' "jevx includes its pinned Codex runtime, so a separate system install is optional."
        printf '%s\n' "If your organization manages Codex, answer no and follow its deployment policy."
        printf '%s' "Install the current standalone Codex CLI from OpenAI now? [y/N] "
    } > /dev/tty
    codex_answer=
    IFS= read -r codex_answer < /dev/tty || codex_answer=
    case $codex_answer in
        y|Y|yes|YES|Yes)
            codex_installer=$temp_dir/codex-install.sh
            note "downloading the official OpenAI Codex installer"
            download "$CODEX_INSTALL_URL" "$codex_installer" || die "could not download the official Codex installer"
            [ -s "$codex_installer" ] || die "the downloaded Codex installer is empty"
            sh "$codex_installer" </dev/tty >/dev/tty 2>/dev/tty || die "the official Codex installer did not complete successfully"
            ;;
        *)
            note "system Codex installation skipped; jevx will use its checksum-matched bundled runtime"
            ;;
    esac
else
    say "No system Codex command was detected. jevx will use its bundled runtime."
    say "Optional official OpenAI installer:"
    say "  curl -fsSL $CODEX_INSTALL_URL | sh"
fi

if [ "${JEVX_SKIP_SETUP-0}" = 1 ]; then
    note "setup skipped; run the installed 'jevx setup' command when ready"
elif [ "$interactive" -eq 1 ]; then
    note "starting the jevx setup wizard"
    "$install_dir/jevx" setup -C "$release_dir" </dev/tty >/dev/tty 2>/dev/tty || die "jevx was installed, but setup did not complete; rerun the installed 'jevx setup' command"
else
    say "Run the interactive setup wizard next:"
    say "  jevx setup"
fi

say "Installation complete."
