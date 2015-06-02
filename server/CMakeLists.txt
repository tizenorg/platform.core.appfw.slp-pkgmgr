# package manager server

SET(PKGMGR_SERVER "pkgmgr-server")
SET(SRCS src/pkgmgr-server.c src/pm-queue.c)

pkg_check_modules(SERVER_DEPS REQUIRED
		cynara-client
		dlog
		ail
		pkgmgr-parser
		pkgmgr-info
		libtzplatform-config)
FOREACH(SERVER_FLAGS ${SERVER_DEPS_CFLAGS})
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SERVER_FLAGS}")
ENDFOREACH(SERVER_FLAGS)

INCLUDE_DIRECTORIES(include)

ADD_EXECUTABLE(${PKGMGR_SERVER} ${SRCS})
TARGET_LINK_LIBRARIES(${PKGMGR_SERVER} pkgmgr_installer pkgmgr_installer_pkg_mgr_server)
TARGET_LINK_LIBRARIES(${PKGMGR_SERVER} ${SERVER_DEPS_LDFLAGS})

CONFIGURE_FILE(org.tizen.slp.pkgmgr.service.in org.tizen.slp.pkgmgr.service @ONLY)
CONFIGURE_FILE(org.tizen.slp.pkgmgr.conf.in org.tizen.slp.pkgmgr.conf @ONLY)

INSTALL(TARGETS ${PKGMGR_SERVER} DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/queue_status DESTINATION ${SYSCONFDIR}/package-manager/server/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.slp.pkgmgr.service DESTINATION ${PREFIX}/share/dbus-1/system-services/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.slp.pkgmgr.conf DESTINATION ${SYSCONFDIR}/dbus-1/system.d/)

ADD_SUBDIRECTORY(po)
