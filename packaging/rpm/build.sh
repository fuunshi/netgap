#!/bin/sh
# Build an RPM from a release binary.
#
#   build.sh <netgap|netgap-gui> <version> <binary> <output-dir>
#
# The spec files build a package from the prebuilt binary rather than from
# source: the release already compiles it once, in the image whose libc the
# package declares, and recompiling for every distribution would make them
# disagree. Run from the repository root; needs rpmbuild.
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

command -v rpmbuild >/dev/null 2>&1 || {
    echo "build.sh: rpmbuild is not installed" >&2
    exit 2
}

topdir=$(mktemp -d)
trap 'rm -rf "$topdir"' EXIT INT TERM
mkdir -p "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SOURCES" "$topdir/SPECS" "$topdir/SRPMS"

cp packaging/rpm/"$package".spec "$topdir/SPECS/"
cp "$binary" "$topdir/SOURCES/$package"
cp LICENSE-MIT LICENSE-APACHE "$topdir/SOURCES/"
if [ "$package" = netgap-gui ]; then
    cp netgap-gui/assets/netgap.desktop netgap-gui/assets/netgap.svg "$topdir/SOURCES/"
fi

rpmbuild -bb \
    --define "_topdir $topdir" \
    --define "_version $version" \
    --target x86_64 \
    "$topdir/SPECS/$package.spec" >/dev/null

rpm_file=$(find "$topdir/RPMS" -name '*.rpm' -type f | head -1)
if [ -z "$rpm_file" ]; then
    echo "build.sh: rpmbuild produced no package" >&2
    exit 1
fi

mkdir -p "$out"
cp "$rpm_file" "$out/"
echo "built $out/$(basename "$rpm_file")"
