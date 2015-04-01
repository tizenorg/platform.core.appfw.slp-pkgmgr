# Test executables
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS}")

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/client/include)

INCLUDE(FindPkgConfig)

pkg_check_modules(pkgs_initdb REQUIRED libsmack ecore dbus-1 ail libxml-2.0 bundle pkgmgr-parser vconf pkgmgr-info libtzplatform-config)
FOREACH(flag ${pkgs_initdb_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)


pkg_check_modules(pkgs_test REQUIRED ecore dbus-1 ail libxml-2.0 bundle pkgmgr-parser vconf pkgmgr-info libtzplatform-config)
FOREACH(flag ${pkgs_test_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(toolpkgs REQUIRED appcore-efl dlog bundle glib-2.0 pkgmgr-parser vconf pkgmgr-info libtzplatform-config)
FOREACH(flag ${toolpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

add_executable(pkgcmd
		pkg_cmd.c)
target_link_libraries(pkgcmd pkgmgr-client ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkgcmd DESTINATION bin)

add_executable(pkginfo
                pkg_info.c)
target_link_libraries(pkginfo pkgmgr-client pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkginfo DESTINATION bin)

add_executable(pkg_getsize
                pkg_getsize.c)
target_link_libraries(pkg_getsize pkgmgr-client pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_getsize DESTINATION bin)

add_executable(pkg_createdb pkg_createdb.c)
target_link_libraries(pkg_createdb ${pkgs_initdb_LDFLAGS})
INSTALL(TARGETS pkg_createdb DESTINATION bin)

add_executable(pkg_createdb_user pkg_createdb_user.c)
target_link_libraries(pkg_createdb_user ${pkgs_initdb_LDFLAGS})
INSTALL(TARGETS pkg_createdb_user DESTINATION bin)

add_executable(pkg_syncdb pkg_syncdb.c)
target_link_libraries(pkg_syncdb ${pkgs_initdb_LDFLAGS})
INSTALL(TARGETS pkg_syncdb DESTINATION bin)

add_executable(pkg_syncdb_user pkg_syncdb_user.c)
target_link_libraries(pkg_syncdb_user ${pkgs_initdb_LDFLAGS})
INSTALL(TARGETS pkg_syncdb_user DESTINATION bin)

add_executable(pkg_clearcache pkg_clearcache.c)
target_link_libraries(pkg_clearcache ${pkgs_test_LDFLAGS})
install(TARGETS pkg_clearcache DESTINATION bin)

add_executable(pkg_initdb pkg_initdb.c)
target_link_libraries(pkg_initdb ${pkgs_initdb_LDFLAGS})
INSTALL(TARGETS pkg_initdb DESTINATION bin)

add_executable(pkg_initdb_user pkg_initdb_user.c)
target_link_libraries(pkg_initdb_user ${pkgs_initdb_LDFLAGS})
INSTALL(TARGETS pkg_initdb_user DESTINATION bin)

add_executable(pkgmgr-install pkgmgr-install.c)
target_link_libraries(pkgmgr-install pkgmgr-client pkgmgr-info ${toolpkgs_LDFLAGS})
install(TARGETS pkgmgr-install DESTINATION bin)

configure_file(org.tizen.pkgmgr-install.xml.in ${CMAKE_BINARY_DIR}/org.tizen.pkgmgr-install.xml @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/org.tizen.pkgmgr-install.xml DESTINATION /usr/share/packages/)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.wac.xml DESTINATION /usr/share/mime/packages/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.tpk.xml DESTINATION /usr/share/mime/packages/)

configure_file(pkgmgr.patch.sh.in pkgmgr.patch.sh @ONLY)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkgmgr.patch.sh DESTINATION ${SYSCONFDIR}/opt/upgrade/)
