#!/bin/sh
# Install the window application for the current user: the binary, its icon
# and a menu entry that starts it with a click.
#
# Run this from the folder the release was unpacked into. Nothing is written
# outside $HOME unless PREFIX is set, and no root is needed.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prefix=${PREFIX:-$HOME/.local}

bindir="$prefix/bin"
appdir="$prefix/share/applications"
icondir="$prefix/share/icons/hicolor/scalable/apps"

mkdir -p "$bindir" "$appdir" "$icondir"

install -m 0755 "$here/netgap-gui" "$bindir/netgap-gui"
install -m 0644 "$here/netgap.svg" "$icondir/netgap.svg"
install -m 0644 "$here/netgap.desktop" "$appdir/netgap.desktop"

# These only rebuild the menu and icon caches; a failure here costs nothing.
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$appdir" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$prefix/share/icons/hicolor" >/dev/null 2>&1 || true
fi

case ":$PATH:" in
    *":$bindir:"*) ;;
    *) echo "note: $bindir is not on PATH; the menu entry works anyway." ;;
esac

echo "Netgap is installed."
echo "Open it from your applications menu, or run: $bindir/netgap-gui"
