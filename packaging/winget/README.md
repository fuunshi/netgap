# winget

`make-manifests.sh` writes the three files winget needs for one version —
version, default locale and installer — into the layout `microsoft/winget-pkgs`
expects. The release workflow runs it for every release and attaches the
result to the release as `netgap-winget-<version>.zip`. The files are not
committed per version: a manifest names one URL and one hash, and a stale one
installs the wrong version.

To make `winget install fuunshi.Netgap` work:

1. Fork `microsoft/winget-pkgs`.
2. Unpack the release's `netgap-winget-<version>.zip` and copy the
   `manifests/` tree it contains into the same path in the fork.
3. Open one pull request for that version. The first one also introduces
   `manifests/f/fuunshi/Netgap/`.
4. After it merges, `winget install fuunshi.Netgap` finds the newest version.

The same directory can be validated and submitted with
`wingetcreate update fuunshi.Netgap` from a Windows machine, which is what the
winget documentation recommends for later versions.

Chocolatey and Scoop are deliberately not shipped: winget is the package
manager that comes with the systems this runs on, and three channels for one
program is three things to keep working.
