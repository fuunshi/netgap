Netgap — window application
===========================

This folder is the point-and-click version of netgap. The scanner is the same
one the command line runs, and scans made here are saved to the same history
`netgap report` reads.

Run it
------

Double-click netgap-gui, or from a terminal:

    ./netgap-gui

Add it to your applications menu (this user only, no root):

    ./install.sh

That copies the binary to ~/.local/bin, the icon to
~/.local/share/icons, and a launcher to ~/.local/share/applications, so
"Netgap" appears in the menu and can be pinned to the dock. Uninstall by
deleting those three files.

Notes
-----

- A desktop session with OpenGL is required. On a headless machine, use the
  command line tool instead.
- Full ARP discovery needs raw sockets. Without root the window falls back to
  unprivileged TCP probing, which finds fewer quiet devices. To give only this
  binary the capability instead of running it as root:

      sudo setcap cap_net_raw+ep ~/.local/bin/netgap-gui

- Opens on a screen of your choice: ./netgap-gui scan, ./netgap-gui devices,
  ./netgap-gui history, plus --light or --dark.
