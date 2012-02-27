# Test executables
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS}")

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/client/include ${CMAKE_SOURCE_DIR}/comm)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs_test REQUIRED ecore dbus-1 ail)
FOREACH(flag ${pkgs_test_CFLAGS})
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

add_executable(pkgmgr-install pkgmgr-install.c)
target_link_libraries(pkgmgr-install pkgmgr-client)
install(TARGETS pkgmgr-install DESTINATION bin)

configure_file(org.tizen.pkgmgr-install.desktop.in ${CMAKE_BINARY_DIR}/org.tizen.pkgmgr-install.desktop @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/org.tizen.pkgmgr-install.desktop DESTINATION /opt/share/applications/)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/mime.wac.xml DESTINATION /usr/share/mime/packages/)

