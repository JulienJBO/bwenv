#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin_dir=${BWENV_BIN_DIR:-"$HOME/.local/bin"}
target="$bin_dir/bwenv"
source="$repo_root/bwenv.py"
marker="# bwenv managed install v1"

mkdir -p "$bin_dir"
if [ -e "$target" ] || [ -L "$target" ]; then
    if [ -L "$target" ] || [ ! -f "$target" ] || [ "$(sed -n '2p' "$target" 2>/dev/null || true)" != "$marker" ]; then
        echo "refusing to replace existing command: $target" >&2
        exit 1
    fi
fi

temporary=$(mktemp "$bin_dir/.bwenv.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
{
    sed -n '1p' "$source"
    printf '%s\n' "$marker"
    sed -n '2,$p' "$source"
} >"$temporary"
chmod 0755 "$temporary"
mv -f "$temporary" "$target"
trap - EXIT HUP INT TERM
printf 'installed %s (standalone copy)\n' "$target"
case ":${PATH:-}:" in
    *":$bin_dir:"*) ;;
    *) printf 'add to your shell profile: export PATH=%s:\$PATH\n' "$bin_dir" ;;
esac
