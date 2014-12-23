%bcond_with wayland

Name:       pkgmgr
Summary:    Packager Manager client library package
Version:    0.2.89
Release:    0
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: %{name}.manifest
Source1002: %{name}-client.manifest
Source1003: %{name}-client-devel.manifest
Source1004: %{name}-server.manifest
Source1005: %{name}-installer.manifest
Source1006: %{name}-installer-devel.manifest
Source1007: %{name}-types-devel.manifest

BuildRequires:  cmake
BuildRequires:  unzip
BuildRequires:  gettext-tools
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(ail)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(notification)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgmgr-info-parser-devel
BuildRequires:  pkgmgr-info-parser
BuildRequires:  libsmack
BuildRequires:  fdupes

%description
Packager Manager client library package for packaging


%package client
Summary:    Package Manager client library develpoment package
Requires:   %{name} = %{version}-%{release}
Requires: shared-mime-info
Requires(post): pkgmgr

%description client
Package Manager client library develpoment package for packaging


%package client-devel
Summary:    Package Manager client library develpoment package
Requires:   %{name} = %{version}-%{release}

%description client-devel
Package Manager client library develpoment package for packaging


%package server
Summary:    Package Manager server
Requires:   %{name} = %{version}-%{release}

%description server
Package Manager server for packaging


%package installer
Summary:    Library for installer frontend/backend
Requires:   %{name} = %{version}-%{release}

%description installer
Library for installer frontend/backend for packaging.


%package installer-devel
Summary:    Dev package for libpkgmgr-installer
Requires:   %{name} = %{version}-%{release}

%description installer-devel
Dev package for libpkgmgr-installer for packaging.


%package types-devel
Summary:    Package Manager manifest parser develpoment package
Requires:   %{name} = %{version}-%{release}

%description types-devel
Package Manager client types develpoment package for packaging


%prep
%setup -q
cp %{SOURCE1001} %{SOURCE1002} %{SOURCE1003} %{SOURCE1004} %{SOURCE1005} %{SOURCE1006} %{SOURCE1007} .

%build
%cmake .

%__make %{?_smp_mflags}

%install
%make_install
rm -f  %{buildroot}%{_bindir}/pkgmgr_backend_sample
rm -f %{buildroot}%{_libdir}/libpkgmgr_backend_lib_sample.so
rm -f %{buildroot}%{_libdir}/libpkgmgr_parser_lib_sample.so

mkdir -p %{buildroot}%{_sysconfdir}/package-manager/backend
mkdir -p %{buildroot}%{_sysconfdir}/package-manager/backendlib
mkdir -p %{buildroot}%{_sysconfdir}/opt/upgrade

mkdir -p %{buildroot}%{_sysconfdir}/package-manager/server

%find_lang package-manager

%fdupes %{buildroot}

%post
/sbin/ldconfig

# For pkgmgr-install:
# Update mime database to support package mime types
update-mime-database %{_datadir}/mime
chsmack -a '*' %{TZ_SYS_RW_PACKAGES}

%post -n pkgmgr-server -p /sbin/ldconfig

%post -n pkgmgr-client -p /sbin/ldconfig

%postun -n pkgmgr-client -p /sbin/ldconfig

%post -n pkgmgr-installer -p /sbin/ldconfig

%postun -n pkgmgr-installer -p /sbin/ldconfig


%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%dir %{_sysconfdir}/package-manager/backend
%dir %{_sysconfdir}/package-manager/backendlib
%dir %{_sysconfdir}/opt/upgrade
%{_sysconfdir}/opt/upgrade/pkgmgr.patch.sh
%{_bindir}/pkgcmd
%attr(06755,root,root) %{_bindir}/pkg_createdb
%attr(755,root,root) %{_bindir}/pkg_createdb_user
%attr(06755,root,root) %{_bindir}/pkg_syncdb
%attr(755,root,root) %{_bindir}/pkg_syncdb_user
#obsolete tools
%attr(06755,root,root) %{_bindir}/pkg_initdb
%attr(755,root,root) %{_bindir}/pkg_initdb_user
%{_bindir}/pkg_getsize
%{_bindir}/pkginfo
%{_bindir}/pkgmgr-install
%attr(-,tizenglobalapp,root) %dir %{TZ_SYS_RW_PACKAGES}
%attr(-,tizenglobalapp,root) %{TZ_SYS_RW_PACKAGES}/org.tizen.pkgmgr-install.xml
%{_datadir}/mime/packages/mime.wac.xml
%{_datadir}/mime/packages/mime.tpk.xml
%exclude %{_includedir}/pkgmgr/comm_client.h
%exclude %{_includedir}/pkgmgr/comm_config.h
%exclude %{_includedir}/pkgmgr/comm_status_broadcast_server.h
%exclude %{_sysconfdir}/package-manager/server/queue_status

%files client
%manifest %{name}-client.manifest
%defattr(-,root,root,-)
%dir %{_sysconfdir}/package-manager
%config %{_sysconfdir}/package-manager/pkg_path.conf
%{_libdir}/libpkgmgr-client.so.*

%files client-devel
%manifest %{name}-client-devel.manifest
%defattr(-,root,root,-)
%{_includedir}/package-manager.h
%{_includedir}/pkgmgr-dbinfo.h
%{_libdir}/pkgconfig/pkgmgr.pc
%{_libdir}/libpkgmgr-client.so

%files server -f package-manager.lang
%manifest %{name}-server.manifest
%defattr(-,root,root,-)
%{_datadir}/dbus-1/system-services/org.tizen.slp.pkgmgr.service
%config %{_sysconfdir}/dbus-1/system.d/org.tizen.slp.pkgmgr.conf
%{_bindir}/pkgmgr-server
%{_sysconfdir}/package-manager/server

%files installer
%manifest %{name}-installer.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_installer.so.*
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so.*
%{_libdir}/libpkgmgr_installer_client.so.*

%files installer-devel
%manifest %{name}-installer-devel.manifest
%defattr(-,root,root,-)
%dir %{_includedir}/pkgmgr
%{_includedir}/pkgmgr/pkgmgr_installer.h
%{_libdir}/pkgconfig/pkgmgr-installer-status-broadcast-server.pc
%{_libdir}/pkgconfig/pkgmgr-installer.pc
%{_libdir}/pkgconfig/pkgmgr-installer-client.pc
%{_libdir}/libpkgmgr_installer.so
%{_libdir}/libpkgmgr_installer_client.so
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so

%files types-devel
%manifest %{name}-types-devel.manifest
%defattr(-,root,root,-)
%{_includedir}/package-manager-types.h
%{_includedir}/package-manager-plugin.h
%{_libdir}/pkgconfig/pkgmgr-types.pc
