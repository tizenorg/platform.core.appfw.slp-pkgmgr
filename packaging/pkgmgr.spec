%bcond_with wayland

Name:       pkgmgr
Summary:    Packager Manager client library package
Version:    0.2.125
Release:    1
Group:      Application Framework/Package Management
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:	pkgmgr_recovery.service
Source1001:	%{name}.manifest
Source1002:	%{name}-client.manifest
Source1003:	%{name}-client-devel.manifest
Source1004:	%{name}-server.manifest
Source1005:	%{name}-installer.manifest
Source1006:	%{name}-installer-devel.manifest
Source1007:	%{name}-types-devel.manifest
BuildRequires:  cmake
BuildRequires:  unzip
BuildRequires:  gettext-tools
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(ail)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(appcore-efl)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgmgr-info-parser-devel
BuildRequires:  pkgmgr-info-parser
BuildRequires:  python-xml


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

%if 0%{?tizen_build_binary_release_type_eng}
export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS ?DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"
%endif

%build
%cmake . \
%if %{with wayland}
    -DX11_SUPPORT=Off
%else
    -DX11_SUPPORT=On
%endif

make %{?jobs:-j%jobs}

%install
%make_install
rm -f  %{buildroot}%{_bindir}/pkgmgr_backend_sample
rm -f %{buildroot}%{_libdir}/libpkgmgr_backend_lib_sample.so
rm -f %{buildroot}%{_libdir}/libpkgmgr_parser_lib_sample.so

mkdir -p %{buildroot}%{_sysconfdir}/package-manager/backend
mkdir -p %{buildroot}%{_sysconfdir}/package-manager/backendlib
mkdir -p %{buildroot}/etc/opt/upgrade

mkdir -p %{buildroot}%{_sysconfdir}/package-manager/server

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/pkgmgr_recovery.service
ln -s ../pkgmgr_recovery.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/pkgmgr_recovery.service

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/%{name}-client
cp LICENSE %{buildroot}/usr/share/license/%{name}-client-devel
cp LICENSE %{buildroot}/usr/share/license/%{name}-server
cp LICENSE %{buildroot}/usr/share/license/%{name}-installer
cp LICENSE %{buildroot}/usr/share/license/%{name}-installer-devel
cp LICENSE %{buildroot}/usr/share/license/%{name}-types-devel

%find_lang package-manager
%post
/sbin/ldconfig

vconftool set -t int memory/pkgmgr/status "0" -f -i -s system::vconf -g 5000

# For pkgmgr-install:
# Update mime database to support package mime types
update-mime-database /usr/share/mime

%post server -p /sbin/ldconfig
%posttrans
#init DB
mkdir -p /usr/share/packages
mkdir -p /opt/share/packages
mkdir -p /opt/share/packages/.recovery/pkgmgr
mkdir -p /opt/share/packages/.recovery/tpk
mkdir -p /opt/share/packages/.recovery/wgt

%post client -p /sbin/ldconfig

%postun client -p /sbin/ldconfig

%post installer -p /sbin/ldconfig

%postun installer -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%defattr(-,root,root,-)
%dir %{_sysconfdir}/package-manager/backend
%dir %{_sysconfdir}/package-manager/backendlib
%dir /etc/opt/upgrade
%{_bindir}/pkgcmd
%{_bindir}/pkg_initdb
%{_bindir}/pkg_smack
%{_bindir}/pkg_fota
%{_bindir}/pkg_getsize
%{_bindir}/pkginfo
%{_bindir}/pkgmgr-install
%dir %{_datadir}/packages
%{_datadir}/packages/org.tizen.pkgmgr-install.xml
%{_datadir}/mime/packages/mime.wac.xml
%{_datadir}/mime/packages/mime.tpk.xml
%exclude %{_includedir}/pkgmgr/comm_client.h
%exclude %{_includedir}/pkgmgr/comm_config.h
%exclude %{_includedir}/pkgmgr/comm_status_broadcast_server.h
%exclude %{_sysconfdir}/package-manager/server/queue_status
%attr(0700,root,root) /etc/opt/upgrade/520.pkgmgr.patch.sh
%attr(0700,root,root) /usr/etc/package-manager/pkg_recovery.sh
%{_libdir}/systemd/system/multi-user.target.wants/pkgmgr_recovery.service
%{_libdir}/systemd/system/pkgmgr_recovery.service
/usr/share/license/%{name}

%files client
%manifest %{name}-client.manifest
%defattr(-,root,root,-)
%dir /etc/package-manager
/etc/package-manager/pkg_path.conf
%{_libdir}/libpkgmgr-client.so.*
/usr/share/license/%{name}-client

%files client-devel
%manifest %{name}-client-devel.manifest
%defattr(-,root,root,-)
%{_includedir}/package-manager.h
%{_includedir}/pkgmgr-dbinfo.h
%{_libdir}/pkgconfig/pkgmgr.pc
%{_libdir}/libpkgmgr-client.so
/usr/share/license/%{name}-client-devel

%files server -f package-manager.lang
%manifest %{name}-server.manifest
%defattr(-,root,root,-)
%{_datadir}/dbus-1/system-services/org.tizen.slp.pkgmgr.service
%{_sysconfdir}/dbus-1/system.d/org.tizen.slp.pkgmgr.conf
%{_bindir}/pkgmgr-server
%{_sysconfdir}/package-manager/server
%{_datadir}/locale/*/LC_MESSAGES/*.mo
/usr/share/license/%{name}-server

%files installer
%manifest %{name}-installer.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_installer.so.*
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so.*
%{_libdir}/libpkgmgr_installer_client.so.*
/usr/share/license/%{name}-installer

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
/usr/share/license/%{name}-installer-devel


%files types-devel
%manifest %{name}-types-devel.manifest
%defattr(-,root,root,-)
%{_includedir}/package-manager-types.h
%{_includedir}/package-manager-plugin.h
%{_libdir}/pkgconfig/pkgmgr-types.pc
/usr/share/license/%{name}-types-devel
