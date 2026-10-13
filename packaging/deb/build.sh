#!/bin/sh
# Build a Debian package from a release binary.
#
#   build.sh <netgap|netgap-gui> <version> <binary> <output-dir>
#
# `netgap` is the static command line binary and depends on nothing; the
# window application loads the desktop's graphics libraries when it starts and
# also installs the icon and the menu entry. Run from the repository root:
# the licence texts and the GUI assets are read from there.
#
# The release workflow calls this after building, inside the same old Ubuntu
# the window application is built in, so the libc floor written into the
# control file matches the binary.
set -eu

package=${1:?usage: build.sh <netgap|netgap-gui> <version> <binary> <output-dir>}
version=${2:?usage: build.sh <netgap|netgap-gui> <version> <binary> <output-dir>}
binary=${3:?usage: build.sh <netgap|netgap-gui> <version> <binary> <output-dir>}
out=${4:?usage: build.sh <netgap|netgap-gui> <version> <binary> <output-dir>}

case "$package" in
netgap | netgap-gui) ;;
*)
    echo "build.sh: unknown package '$package'" >&2
    exit 2
    ;;
esac

if [ ! -x "$binary" ]; then
    echo "build.sh: $binary is not an executable" >&2
    exit 2
fi

# The release archives are x86_64 only, so there is one architecture to name.
# Change this when a second one is built.
arch=amd64

# Directory modes are copied into the package; the build user's umask should
# not decide whether /usr/share is group-writable.
umask 022

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT INT TERM
chmod 0755 "$staging"

install -D -m 0755 "$binary" "$staging/usr/bin/$package"

docdir="$staging/usr/share/doc/$package"
mkdir -p "$docdir"
{
    echo "This package was built from https://github.com/fuunshi/netgap."
    echo "Upstream author: Pranil Shrestha."
    echo
    echo "Licence: MIT or Apache-2.0, at your option. Both texts follow."
    echo
    echo "---- MIT ----"
    echo
    cat LICENSE-MIT
    echo
    echo "---- Apache-2.0 ----"
    echo
    cat LICENSE-APACHE
} >"$docdir/copyright"
chmod 0644 "$docdir/copyright"

if [ "$package" = netgap-gui ]; then
    assets=netgap-gui/assets
    install -D -m 0644 "$assets/netgap.svg" \
        "$staging/usr/share/icons/hicolor/scalable/apps/netgap.svg"
    install -D -m 0644 "$assets/netgap.desktop" \
        "$staging/usr/share/applications/netgap.desktop"

    # The menu and icon caches are what the desktop reads; refresh them on
    # install and removal when the tools are there, and say nothing when they
    # are not. Cache refreshes are the only maintainer scripts this package
    # needs.
    mkdir -p "$staging/DEBIAN"
    cat >"$staging/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = configure ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
    fi
fi
exit 0
EOF
    cat >"$staging/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = remove ] || [ "$1" = purge ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
    fi
fi
exit 0
EOF
    chmod 0755 "$staging/DEBIAN/postinst" "$staging/DEBIAN/postrm"
fi

installed_size=$(du -sk "$staging" | cut -f1)

mkdir -p "$staging/DEBIAN"
{
    echo "Package: $package"
    echo "Version: $version"
    echo "Architecture: $arch"
    echo "Maintainer: Pranil Shrestha <pranilshrestha2016@gmail.com>"
    echo "Homepage: https://github.com/fuunshi/netgap"
    echo "Section: net"
    echo "Priority: optional"
    echo "Installed-Size: $installed_size"
    if [ "$package" = netgap-gui ]; then
        # The binary is linked against the glibc of the build image
        # (Ubuntu 22.04, glibc 2.35). The graphics and input libraries are
        # opened when the window starts, so they are recommendations: the
        # command line works without them, and the window says which library
        # it could not find.
        echo "Depends: libc6 (>= 2.35), libgcc-s1"
        echo "Recommends: libgl1, libegl1, libxkbcommon0, libwayland-client0, libx11-6, libxcursor1, libxrandr2, libxi6"
    fi
    echo "Description: LAN security scanner"
    if [ "$package" = netgap-gui ]; then
        echo " The window application of netgap: a dashboard, a scan screen, a"
        echo " searchable device list and the scan history. It runs the same"
        echo " scans as the command line and reads the same history."
    else
        echo " Finds the devices on the local network, what they expose and"
        echo " what that means, from a terminal. Includes the interactive"
        echo " view (netgap ui) and the reports."
    fi
} >"$staging/DEBIAN/control"
chmod 0644 "$staging/DEBIAN/control"

mkdir -p "$out"
deb="$out/${package}_${version}_${arch}.deb"
# --root-owner-group writes root:root even when the build runs as a user.
dpkg-deb --build --root-owner-group "$staging" "$deb" >/dev/null
echo "built $deb"
