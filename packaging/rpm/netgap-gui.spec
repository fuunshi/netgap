Name:           netgap-gui
Version:        %{_version}
Release:        1%{?dist}
Summary:        LAN security scanner, window application

License:        MIT OR Apache-2.0
URL:            https://github.com/fuunshi/netgap
Source0:        netgap-gui
Source1:        LICENSE-MIT
Source2:        LICENSE-APACHE
Source3:        netgap.desktop
Source4:        netgap.svg

# The binary is prebuilt and copied in %install; there is nothing to compile
# here, and the architecture comes from rpmbuild's --target.

# rpmbuild reads the ELF headers and adds the libc floor itself. The graphics
# and input libraries are opened when the window starts, so they are only
# recommended: the command line package works without them, and the window
# says which library it could not find.
Recommends:     libxkbcommon, libX11, mesa-libGL

%description
The window application of netgap: a dashboard, a scan screen, a searchable
device list and the scan history. It runs the same scans as the command line
and reads the same history.

%prep

%build

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/netgap-gui
install -D -m 0644 %{SOURCE3} %{buildroot}%{_datadir}/applications/netgap.desktop
install -D -m 0644 %{SOURCE4} %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/netgap.svg
install -D -m 0644 %{SOURCE1} %{buildroot}%{_datadir}/licenses/netgap-gui/LICENSE-MIT
install -D -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/licenses/netgap-gui/LICENSE-APACHE

%post
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database %{_datadir}/applications >/dev/null 2>&1 || :
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t %{_datadir}/icons/hicolor >/dev/null 2>&1 || :
fi

%postun
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database %{_datadir}/applications >/dev/null 2>&1 || :
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t %{_datadir}/icons/hicolor >/dev/null 2>&1 || :
fi

%files
%{_bindir}/netgap-gui
%{_datadir}/applications/netgap.desktop
%{_datadir}/icons/hicolor/scalable/apps/netgap.svg
%license %{_datadir}/licenses/netgap-gui/LICENSE-MIT
%license %{_datadir}/licenses/netgap-gui/LICENSE-APACHE
