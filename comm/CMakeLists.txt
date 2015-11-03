### Description
# Communication modules for pkg-mgr client lib and server process
# By Youmin Ha <youmin.ha@samsung.com>

cmake_minimum_required(VERSION 2.6)
#set(CMAKE_SKIP_BUILD_RPATH true)
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)


### Versioning
if(DEFINED ${VERSION})
	message("VERSION: ${VERSION}")
else()
	message("VERSION is not defined. set it as 0.1.0")
	set(VERSION 0.1.0)
endif()
if(DEFINED ${VERSION_MAJOR})
	message("VERSION_MAJOR: ${VERSION_MAJOR}")
else()
	message( "VERSION_MAJOR is not defined. set it as 0")
	set(VERSION_MAJOR 0)
endif()
message(STATUS "version/major : ${VERSION} / ${VERSION_MAJOR}")

### Get required CFLAGS, LDFLAGS from pkg-config

include(FindPkgConfig)
pkg_check_modules(installer_client_pkgs REQUIRED glib-2.0 gio-2.0 dlog)
foreach(flag ${installer_client_pkgs_CFLAGS})
	set(installer_client_pkgs_CFLAGS_str "${installer_client_pkgs_CFLAGS_str} ${flag}")
endforeach()

pkg_check_modules(installer_pkgs REQUIRED glib-2.0 gio-2.0 dlog pkgmgr-info)
foreach(flag ${installer_pkgs_CFLAGS})
	set(installer_pkgs_CFLAGS_str "${installer_pkgs_CFLAGS_str} ${flag}")
endforeach()

### Build modules

## client for apps
# Send request, get status signal
add_library(pkgmgr_installer_client SHARED
		comm_client_gdbus.c
		)
set_target_properties(pkgmgr_installer_client PROPERTIES SOVERSION ${VERSION_MAJOR})
set_target_properties(pkgmgr_installer_client PROPERTIES VERSION ${VERSION})
set_target_properties(pkgmgr_installer_client PROPERTIES COMPILE_FLAGS "${installer_client_pkgs_CFLAGS_str}")
target_link_libraries(pkgmgr_installer_client ${installer_client_pkgs_LDFLAGS})

## pkgmgr_installer object (by youmin.ha)
# This library is for installer backend
add_library(pkgmgr_installer SHARED pkgmgr_installer.c)
set_target_properties(pkgmgr_installer PROPERTIES SOVERSION ${VERSION_MAJOR})
set_target_properties(pkgmgr_installer PROPERTIES VERSION ${VERSION})
set_target_properties(pkgmgr_installer PROPERTIES COMPILE_FLAGS "${installer_pkgs_CFLAGS_str}")
target_link_libraries(pkgmgr_installer ${installer_pkgs_LDFLAGS})


### Create pc file
configure_file(pkgmgr-installer-client.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer-client.pc @ONLY)
configure_file(pkgmgr-installer.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer.pc @ONLY)


## Install
INSTALL(TARGETS
			pkgmgr_installer_client
			pkgmgr_installer
            DESTINATION ${LIB_INSTALL_DIR}
		COMPONENT RuntimeLibraries)
INSTALL(FILES
			comm_client.h
			comm_config.h
			pkgmgr_installer.h
		DESTINATION include/pkgmgr)


INSTALL(FILES
		${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer-client.pc
		${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer.pc
        DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
