#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bin_dir=${BWENV_BIN_DIR:-"$HOME/.local/bin"}
target="$bin_dir/bwenv"
source="$repo_root/bwenv.py"

mkdir -p "$bin_dir"
if [ -e "$target" ] || [ -L "$target" ]; then
    current=$(readlink "$target" 2>/dev/null || true)
    if [ "$current" != "$source" ]; then
        echo "refusing to replace existing command: $target" >&2
        exit 1
    fi
fi

ln -sfn "$source" "$target"
chmod 755 "$source"
printf 'installed %s -> %s\n' "$target" "$source"
case ":${PATH:-}:" in
    *":$bin_dir:"*) ;;
    *) printf 'add to your shell profile: export PATH=%s:\$PATH\n' "$bin_dir" ;;
esac
