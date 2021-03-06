# 
# Copyright (c) 2008 ~ 2010 Samsung Electronics Co., Ltd.
# All rights reserved
#

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

PROJECT(package-manager C)

SET(VERSION 0.1.68)
SET(VERSION_MAJOR 0)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")


set(CMAKE_SKIP_BUILD_RPATH true)

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/comm ${CMAKE_SOURCE_DIR}/parser)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED security-server dlog elementary evas ecore appcore-efl ecore-x ail ecore-file libxml-2.0)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(libpkgs REQUIRED dbus-glib-1 dlog aul ail)

FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(pm_dir "${CMAKE_SOURCE_DIR}")
SET(pm_inc_dir "${pm_dir}/include")
SET(pm_c_src_dir "${pm_dir}/client/src")
SET(pm_c_inc_dir "${pm_dir}/client/include")
SET(pm_s_src_dir "${pm_dir}/server/src")
SET(pm_s_inc_dir "${pm_dir}/server/include")
SET(pm_t_inc_dir "${pm_dir}/types/include")

## About debug
SET(debug_type "-DPM_CONSOLE_USE") 		# for debug - use console window

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

##################
## build comm libraries
add_subdirectory(comm)
add_subdirectory(parser)
add_subdirectory(tool)
add_subdirectory(types)

###################################################################################################
## for libpkgmgr-client.so (library)
SET(PKGMGR_CLIENT "pkgmgr-client")
SET(libpkgmgr-client_SOURCES ${pm_c_src_dir}/pkgmgr-info.c ${pm_c_src_dir}/pkgmgr-dbinfo.c ${pm_c_src_dir}/pkgmgr-internal.c ${pm_c_src_dir}/pkgmgr.c)
SET(libpkgmgr-client_LDFLAGS " -module -avoid-version ")
SET(libpkgmgr-client_CFLAGS  " ${CFLAGS} -fPIC -I${pm_c_inc_dir} -I${pm_inc_dir} -I${pm_t_inc_dir} ${debug_type}")

ADD_LIBRARY(${PKGMGR_CLIENT} SHARED ${libpkgmgr-client_SOURCES})
SET_TARGET_PROPERTIES(${PKGMGR_CLIENT} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${PKGMGR_CLIENT} PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(${PKGMGR_CLIENT} PROPERTIES COMPILE_FLAGS "${libpkgmgr-client_CFLAGS}")
TARGET_LINK_LIBRARIES(${PKGMGR_CLIENT} pkgmgr_installer_client pkgmgr_installer_status_broadcast_server pkgmgr_parser ${libpkgs_LDFLAGS})
###################################################################################################

###################################################################################################
## for pkgmgr-server (binary)
SET(pkgmgr-server_SOURCES ${pm_s_src_dir}/pkgmgr-server.c ${pm_s_src_dir}/pm-queue.c)
SET(pkgmgr-server_CFLAGS " -I. -I${pm_inc_dir} -I${pm_s_inc_dir} -I${pm_dir}/comm ${debug_type} -D_GNU_SOURCE ")
SET(pkgmgr-server_LDFLAGS ${pkgs_LDFLAGS})

ADD_EXECUTABLE(pkgmgr-server ${pkgmgr-server_SOURCES})
TARGET_LINK_LIBRARIES(pkgmgr-server pkgmgr_installer pkgmgr_installer_pkg_mgr_server)
TARGET_LINK_LIBRARIES(pkgmgr-server ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(pkgmgr-server PROPERTIES COMPILE_FLAGS "${pkgmgr-server_CFLAGS}")
####################################################################################################

CONFIGURE_FILE(pkgmgr.pc.in pkgmgr.pc @ONLY)
configure_file(org.tizen.slp.pkgmgr.service.in org.tizen.slp.pkgmgr.service @ONLY)
configure_file(pkg_path.conf.in pkg_path.conf @ONLY)

#INSTALL(FILES ${CMAKE_BINARY_DIR}/libpkgmgr-client.so DESTINATION lib)
INSTALL(TARGETS ${PKGMGR_CLIENT} DESTINATION lib COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_BINARY_DIR}/pkgmgr-server DESTINATION bin PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr.pc DESTINATION lib/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/client/include/package-manager.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.slp.pkgmgr.service DESTINATION ${PREFIX}/share/dbus-1/services/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkg_path.conf DESTINATION ${PREFIX}/etc/package-manager/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/queue_status DESTINATION etc/package-manager/server/)

####################################################################################################
add_subdirectory(installers)
# i18n
add_subdirectory(po)
