#!/bin/sh
# Install wardctl system-wide.
#
#   sudo ./install.sh                 install to /usr/local (default)
#   ./install.sh --prefix DIR         install elsewhere (root not needed if DIR is writable)
#
# Installs only wardctl's own files:
#   PREFIX/lib/wardctl/wardctl/   the Python package (root-owned, read-only)
#   PREFIX/lib/wardctl/MANIFEST   list of installed files (used by uninstall.sh)
#   PREFIX/bin/wardctl            launcher
#   PREFIX/share/doc/wardctl/     README and config example
# It does not install Python packages with pip, does not touch system Python,
# does not run apt-get, and does not create any per-user state.
# Requirements (all in a standard Debian 13 install): python3 (>= 3.11),
# apt, dpkg, gpgv, and sudo for self-elevation.
set -eu

PREFIX=/usr/local
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) [ $# -ge 2 ] || { echo "install.sh: --prefix needs a directory" >&2; exit 2; }
                  PREFIX=$2; shift 2 ;;
        --prefix=*) PREFIX=${1#--prefix=}; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "install.sh: unknown option: $1" >&2; exit 2 ;;
    esac
done
case "$PREFIX" in
    /*) ;;
    *) echo "install.sh: --prefix must be an absolute path" >&2; exit 2 ;;
esac

SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
LIBDIR="$PREFIX/lib/wardctl"
BINDIR="$PREFIX/bin"
DOCDIR="$PREFIX/share/doc/wardctl"
LAUNCHER="$BINDIR/wardctl"
MARKER="# WARDCTL-LAUNCHER"

if [ "$PREFIX" = /usr/local ] && [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: installing to /usr/local requires root: sudo $0" >&2
    exit 1
fi

PYTHON=/usr/bin/python3
if [ ! -x "$PYTHON" ]; then
    echo "install.sh: $PYTHON not found. Install it with: sudo apt-get install python3" >&2
    exit 1
fi
if ! "$PYTHON" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "install.sh: Python 3.11 or newer is required" >&2
    exit 1
fi
[ -f "$SRC/wardctl/__init__.py" ] || { echo "install.sh: run from an wardctl source tree" >&2; exit 1; }

if [ -e "$LAUNCHER" ] && ! grep -q "^$MARKER" "$LAUNCHER" 2>/dev/null; then
    echo "install.sh: $LAUNCHER exists and was not installed by wardctl; refusing to overwrite" >&2
    exit 1
fi

umask 022
install -d -m 0755 "$LIBDIR" "$BINDIR" "$DOCDIR"

# Stage the new package next to the old one, then swap, so a rerun never
# leaves a half-written tree.
STAGE=$(mktemp -d "$LIBDIR/.stage.XXXXXX")
trap 'rm -rf -- "$STAGE"' EXIT
(cd "$SRC" && find wardctl -type d -name __pycache__ -prune -o -type f \
    \( -name '*.py' -o -name '*.gpg' -o -name '*.asc' \) -print) | sort > "$STAGE/files"
while IFS= read -r rel; do
    install -D -m 0644 "$SRC/$rel" "$STAGE/$rel"
done < "$STAGE/files"
find "$STAGE/wardctl" -type d -exec chmod 0755 {} +
if [ -d "$LIBDIR/wardctl" ]; then
    mv -- "$LIBDIR/wardctl" "$STAGE/old"
fi
mv -- "$STAGE/wardctl" "$LIBDIR/wardctl"

TMP_LAUNCHER=$(mktemp "$BINDIR/.wardctl.XXXXXX")
cat > "$TMP_LAUNCHER" <<EOF
#!$PYTHON -I
$MARKER (installed by install.sh; removed by uninstall.sh)
import sys
sys.path.insert(0, "$LIBDIR")
from wardctl.cli import main
sys.exit(main())
EOF
chmod 0755 "$TMP_LAUNCHER"
mv -f -- "$TMP_LAUNCHER" "$LAUNCHER"

install -m 0644 "$SRC/README.md" "$DOCDIR/README.md"
install -m 0644 "$SRC/examples/config.example.json" "$DOCDIR/config.example.json"
[ -f "$SRC/docs/SOURCES.md" ] && install -m 0644 "$SRC/docs/SOURCES.md" "$DOCDIR/SOURCES.md"

{
    echo "$LAUNCHER"
    sed "s|^|$LIBDIR/|" "$STAGE/files"
    echo "$DOCDIR/README.md"
    echo "$DOCDIR/config.example.json"
    [ -f "$DOCDIR/SOURCES.md" ] && echo "$DOCDIR/SOURCES.md"
} > "$LIBDIR/MANIFEST"
chmod 0644 "$LIBDIR/MANIFEST"

"$PYTHON" -I -m compileall -q "$LIBDIR/wardctl" >/dev/null 2>&1 || true

echo "wardctl installed: $LAUNCHER"
echo "Next (as your normal user):  wardctl init"
