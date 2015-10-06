# Test executables
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS}")

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/client/include)

INCLUDE(FindPkgConfig)

pkg_check_modules(pkgs_initdb REQUIRED libsmack libxml-2.0 bundle pkgmgr-parser pkgmgr-info libtzplatform-config)
FOREACH(flag ${pkgs_initdb_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(pkgs_test REQUIRED dlog glib-2.0 libxml-2.0 bundle pkgmgr-parser pkgmgr-info libtzplatform-config security-manager)
FOREACH(flag ${pkgs_test_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

ADD_EXECUTABLE(pkgcmd pkg_cmd.c)
TARGET_LINK_LIBRARIES(pkgcmd pkgmgr-client ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkgcmd DESTINATION bin)

ADD_EXECUTABLE(pkginfo pkg_info.c)
TARGET_LINK_LIBRARIES(pkginfo pkgmgr-client pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkginfo DESTINATION bin)

ADD_EXECUTABLE(pkg_privilege pkg_privilege.c)
TARGET_LINK_LIBRARIES(pkg_privilege ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_privilege DESTINATION bin)

ADD_EXECUTABLE(pkg_install_ug pkg_install_ug.c)
TARGET_LINK_LIBRARIES(pkg_install_ug ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_install_ug DESTINATION bin)

ADD_EXECUTABLE(pkg_getsize pkg_getsize.c)
TARGET_LINK_LIBRARIES(pkg_getsize pkgmgr-client pkgmgr_installer ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_getsize DESTINATION bin)

ADD_EXECUTABLE(pkg_clearcache pkg_clearcache.c)
TARGET_LINK_LIBRARIES(pkg_clearcache ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_clearcache DESTINATION bin)

ADD_EXECUTABLE(pkg_initdb pkg_initdb.c)
TARGET_LINK_LIBRARIES(pkg_initdb ${pkgs_initdb_LDFLAGS})
INSTALL(TARGETS pkg_initdb DESTINATION bin)
INSTALL(FILES 10_package-manager-add.post  DESTINATION ${SYSCONF_INSTALL_DIR}/gumd/useradd.d/)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.wac.xml DESTINATION /usr/share/mime/packages/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.tpk.xml DESTINATION /usr/share/mime/packages/)

CONFIGURE_FILE(pkgmgr.patch.sh.in pkgmgr.patch.sh @ONLY)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pkgmgr.patch.sh DESTINATION ${SYSCONFDIR}/opt/upgrade/)
