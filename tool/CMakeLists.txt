# Test executables
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS}")

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/client/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs_test REQUIRED ecore dbus-1 ail libxml-2.0 bundle pkgmgr-parser pkgmgr-info)
FOREACH(flag ${pkgs_test_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(toolpkgs REQUIRED appcore-efl dlog bundle glib-2.0 pkgmgr-info pkgmgr-parser)
FOREACH(flag ${libpkgs_CFLAGS})
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

add_executable(pkg_initdb
                pkg_initdb.c)
target_link_libraries(pkg_initdb ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkg_initdb DESTINATION bin)


add_executable(pkgmgr-install pkgmgr-install.c)
target_link_libraries(pkgmgr-install pkgmgr-client pkgmgr-info ${toolpkgs_LDFLAGS})
install(TARGETS pkgmgr-install DESTINATION bin)

configure_file(org.tizen.pkgmgr-install.xml.in ${CMAKE_BINARY_DIR}/org.tizen.pkgmgr-install.xml @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/org.tizen.pkgmgr-install.xml DESTINATION /usr/share/packages/)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.wac.xml DESTINATION /usr/share/mime/packages/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.tpk.xml DESTINATION /usr/share/mime/packages/)

