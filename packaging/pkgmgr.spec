#sbs-git:slp/pkgs/s/slp-pkgmgr pkgmgr 0.1.103 29b53909a5d6e8728429f0a188177eac691cb6ce
Name:       pkgmgr
Summary:    Packager Manager client library package
Version:    0.2.122
Release:    1
Group:      System/Libraries
License:    Apache License, Version 2.0
Source0:    %{name}-%{version}.tar.gz
Source1:	pkgmgr_recovery.service
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

Requires(post): ail
Requires(post): pkgmgr-info

%package client
Summary:    Package Manager client library develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires: shared-mime-info
Requires(post): pkgmgr

%description client
Package Manager client library develpoment package for packaging

%package client-devel
Summary:    Package Manager client library develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description client-devel
Package Manager client library develpoment package for packaging

%package server
Summary:    Package Manager server
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description server
Package Manager server for packaging

%package installer
Summary:    Library for installer frontend/backend.
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description installer
Library for installer frontend/backend for packaging.

%package installer-devel
Summary:    Dev package for libpkgmgr-installer
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description installer-devel
Dev package for libpkgmgr-installer for packaging.


%package types-devel
Summary:    Package Manager manifest parser develpoment package
Group:      TO_BE/FILLED_IN
Requires:   %{name} = %{version}-%{release}

%description types-devel
Package Manager client types develpoment package for packaging


%prep
%setup -q

%if 0%{?tizen_build_binary_release_type_eng}
export CFLAGS="$CFLAGS -DTIZEN_ENGINEER_MODE"
export CXXFLAGS="$CXXFLAGS ?DTIZEN_ENGINEER_MODE"
export FFLAGS="$FFLAGS -DTIZEN_ENGINEER_MODE"
%endif

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}

%build

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
install -m 0644 %SOURCE1 %{buildroot}%{_libdir}/systemd/system/pkgmgr_recovery.service
ln -s ../pkgmgr_recovery.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/pkgmgr_recovery.service

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post
/sbin/ldconfig

mkdir -p /usr/etc/package-manager/backend
mkdir -p /usr/etc/package-manager/backendlib
mkdir -p /etc/opt/upgrade

vconftool set -t int memory/pkgmgr/status "0" -f -i -s system::vconf -g 5000

# For pkgmgr-install:
# Update mime database to support package mime types
update-mime-database /usr/share/mime

%posttrans
#init DB
mkdir -p /usr/share/packages
mkdir -p /opt/share/packages
mkdir -p /opt/share/packages/.recovery/pkgmgr
mkdir -p /opt/share/packages/.recovery/tpk
mkdir -p /opt/share/packages/.recovery/wgt

mkdir -p /usr/share/applications
mkdir -p /opt/share/applications
mkdir -p /opt/dbspace/

pkg_smack

chsmack -a 'pkgmgr::db' /opt/dbspace/.pkgmgr_parser.db*
chsmack -a 'pkgmgr::db' /opt/dbspace/.pkgmgr_cert.db*
chsmack -a 'ail::db' /opt/dbspace/.app_info.db*
rm -rf /opt/usr/apps/tmp/pkgmgr_tmp.txt

%post server

/sbin/ldconfig
mkdir -p /usr/etc/package-manager/server

%post client -p /sbin/ldconfig

%postun client -p /sbin/ldconfig

%post installer -p /sbin/ldconfig

%postun installer -p /sbin/ldconfig

%files
%manifest pkgmgr.manifest
%defattr(-,root,root,-)
%{_bindir}/pkgcmd
%{_bindir}/pkg_initdb
%{_bindir}/pkg_smack
%{_bindir}/pkg_fota
%{_bindir}/pkg_getsize
%{_bindir}/pkginfo
%{_bindir}/pkgmgr-install
%{_datadir}/packages/org.tizen.pkgmgr-install.xml
%{_datadir}/mime/packages/mime.wac.xml
%{_datadir}/mime/packages/mime.tpk.xml
%{_libdir}/libpkgmgr_parser_lib_sample.so
%exclude %{_bindir}/pkgmgr_backend_sample
%exclude %{_includedir}/pkgmgr/comm_client.h
%exclude %{_includedir}/pkgmgr/comm_config.h
%exclude %{_includedir}/pkgmgr/comm_status_broadcast_server.h
%exclude %{_libdir}/libpkgmgr_backend_lib_sample.so
%exclude /usr/etc/package-manager/server/queue_status
%attr(0700,root,root) /etc/opt/upgrade/pkgmgr.patch.sh
%attr(0700,root,root) /usr/etc/package-manager/pkg_recovery.sh
%{_libdir}/systemd/system/multi-user.target.wants/pkgmgr_recovery.service
%{_libdir}/systemd/system/pkgmgr_recovery.service
/usr/share/license/%{name}

%files client
%manifest pkgmgr-client.manifest
%defattr(-,root,root,-)
%{_prefix}/etc/package-manager/pkg_path.conf
%{_libdir}/libpkgmgr-client.so.*

%files client-devel
%defattr(-,root,root,-)
%{_includedir}/package-manager.h
%{_includedir}/pkgmgr-dbinfo.h
%{_libdir}/pkgconfig/pkgmgr.pc
%{_libdir}/libpkgmgr-client.so

%files server
%manifest pkgmgr-server.manifest
%defattr(-,root,root,-)
%{_datadir}/dbus-1/services/org.tizen.slp.pkgmgr.service
%{_bindir}/pkgmgr-server
%{_datadir}/locale/*/LC_MESSAGES/*.mo

%files installer
%manifest pkgmgr-installer.manifest
%defattr(-,root,root,-)
%{_libdir}/libpkgmgr_installer.so.*
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so.*
%{_libdir}/libpkgmgr_installer_client.so.*

%files installer-devel
%defattr(-,root,root,-)
%{_includedir}/pkgmgr/pkgmgr_installer.h
%{_libdir}/pkgconfig/pkgmgr-installer-status-broadcast-server.pc
%{_libdir}/pkgconfig/pkgmgr-installer.pc
%{_libdir}/pkgconfig/pkgmgr-installer-client.pc
%{_libdir}/libpkgmgr_installer.so
%{_libdir}/libpkgmgr_installer_client.so
%{_libdir}/libpkgmgr_installer_status_broadcast_server.so


%files types-devel
%defattr(-,root,root,-)
%{_includedir}/package-manager-types.h
%{_includedir}/package-manager-plugin.h
%{_libdir}/pkgconfig/pkgmgr-types.pc
