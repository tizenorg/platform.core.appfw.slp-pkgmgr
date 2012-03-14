Name:       slp-pkgmgr
Summary:    Packager Manager client library package
Version:    0.1.100
Release:    1
Group:      TO_BE/FILLED_IN
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(ail)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  gettext-tools


%description
Packager Manager client library package for packaging


%package client
Summary:    Package Manager client library develpoment package
Group:      TO_BE/FILLED_IN
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description client
Package Manager client library develpoment package for packaging

%package client-devel
Summary:    Package Manager client library develpoment package
Group:      TO_BE/FILLED_IN

%description client-devel
Package Manager client library develpoment package for packaging

%package server
Summary:    Package Manager server
Group:      TO_BE/FILLED_IN

%description server
Package Manager server for packaging

%package installer
Summary:    Library for installer frontend/backend.
Group:      TO_BE/FILLED_IN
Requires(post): /sbin/ldconfig, /usr/bin/update-mime-database
Requires(postun): /sbin/ldconfig

%description installer
Library for installer frontend/backend for packaging.

%package installer-devel
Summary:    Dev package for libpkgmgr-installer
Group:      TO_BE/FILLED_IN

%description installer-devel
Dev package for libpkgmgr-installer for packaging.

%package types-devel
Summary:    Package Manager client types develpoment package
Group:      TO_BE/FILLED_IN

%description types-devel
Package Manager client types develpoment package for packaging


%prep
%setup -q


%build
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?jobs:-j%jobs}

%install
%make_install

mkdir -p %{buildroot}/usr/etc/package-manager/frontend
mkdir -p %{buildroot}/usr/etc/package-manager/backend
mkdir -p %{buildroot}/usr/etc/package-manager/server

%find_lang package-manager

%post server

/sbin/ldconfig

%post client -p /sbin/ldconfig

%postun client -p /sbin/ldconfig

%post installer 
/sbin/ldconfig
update-mime-database /usr/share/mime

%postun installer -p /sbin/ldconfig


%files
%exclude %{_bindir}/pkgmgr_backend_sample
%exclude %{_includedir}/pkgmgr/comm_client.h
%exclude %{_includedir}/pkgmgr/comm_config.h
%exclude %{_includedir}/pkgmgr/comm_status_broadcast_server.h
%exclude %{_libdir}/libpkgmgr_backend_lib_sample.so
%exclude /usr/etc/package-manager/server/queue_status


%files client -f package-manager.lang
%{_prefix}/etc/package-manager/pkg_path.conf
%{_datadir}/mime/packages/mime.wac.xml
%{_bindir}/pkgmgr-install
%{_libdir}/libpkgmgr-client.so.*
/usr/bin/pkgcmd
/opt/share/applications/org.tizen.pkgmgr-install.desktop

%files client-devel
%{_includedir}/package-manager.h
%{_libdir}/pkgconfig/pkgmgr.pc
%{_libdir}/libpkgmgr-client.so

%files server
%{_datadir}/dbus-1/services/org.tizen.slp.pkgmgr.service
%{_bindir}/pkgmgr-server
%dir /usr/etc/package-manager/frontend
%dir /usr/etc/package-manager/backend
%dir /usr/etc/package-manager/server


%files installer
%{_libdir}/libpkgmgr_installer.so.*
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so.*
%{_libdir}/libpkgmgr_installer_client.so.*

%files installer-devel
%{_includedir}/pkgmgr/pkgmgr_installer.h
%{_libdir}/pkgconfig/pkgmgr-installer-status-broadcast-server.pc
%{_libdir}/pkgconfig/pkgmgr-installer.pc
%{_libdir}/pkgconfig/pkgmgr-installer-client.pc
%{_libdir}/libpkgmgr_installer.so
%{_libdir}/libpkgmgr_installer_client.so
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so

%files types-devel
%{_includedir}/package-manager-types.h
%{_includedir}/package-manager-plugin.h
%{_libdir}/pkgconfig/pkgmgr-types.pc
