Name:           netgap
Version:        %{_version}
Release:        1%{?dist}
Summary:        LAN security scanner

License:        MIT OR Apache-2.0
URL:            https://github.com/fuunshi/netgap
Source0:        netgap
Source1:        LICENSE-MIT
Source2:        LICENSE-APACHE

# The binary is prebuilt and copied in %install; there is nothing to compile
# here, and the architecture comes from rpmbuild's --target.

%description
Finds the devices on the local network, what they expose and what that means,
from a terminal. Includes the interactive view (netgap ui) and the reports.

%prep

%build

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/netgap
install -D -m 0644 %{SOURCE1} %{buildroot}%{_datadir}/licenses/netgap/LICENSE-MIT
install -D -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/licenses/netgap/LICENSE-APACHE

%files
%{_bindir}/netgap
%license %{_datadir}/licenses/netgap/LICENSE-MIT
%license %{_datadir}/licenses/netgap/LICENSE-APACHE
