# AUR

Two packages, built from the source tag:

- `netgap` — the command line, `netgap ui`, the reports.
- `netgap-gui` — the window application, with its menu entry and icon.

Neither is on the AUR yet: publishing a package means pushing these files to
the AUR repository under the maintainer's account, which is a separate step
from having them.

`makepkg --printsrcinfo` produced the `.SRCINFO` files; regenerate them
whenever the `PKGBUILD` changes:

```sh
cd packaging/aur/netgap && makepkg --printsrcinfo > .SRCINFO
```

`pkgver` tracks the highest release tag. Releases before v1.0.10 carry the
workspace version in `Cargo.toml` rather than the tag's, so a package built
from those tags reports 1.0.0 in `netgap --version`; from v1.0.10 on, the
`NETGAP_RELEASE_VERSION` export in `build()` makes it match `pkgver`.

The source URL is `git+https://github.com/fuunshi/netgap.git`. The repository
has to be public before these packages can be built by anyone else; while it
is private, `makepkg` will fail to clone.
