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
pkg_check_modules(comm_pkgs REQUIRED dbus-1 glib-2.0 dbus-glib-1 gio-2.0 gio-unix-2.0 dlog pkgmgr-info db-util)

foreach(flag ${comm_pkgs_CFLAGS})
	set(comm_pkgs_CFLAGS_str "${comm_pkgs_CFLAGS_str} ${flag}")
endforeach()


### Set current binary dir to be included (for generated *.h files)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

### Create dbus-glib bindings headers (client/server) from xml by dbus-binding-tool

# comm_pkg_mgr : package manger interface (client - package manager process)
add_custom_target(comm_pkg_mgr_client_dbus_bindings.h
	COMMAND dbus-binding-tool --prefix=pkgmgr --mode=glib-client 
			${CMAKE_CURRENT_SOURCE_DIR}/comm_pkg_mgr.xml 
			--output=${CMAKE_CURRENT_BINARY_DIR}/comm_pkg_mgr_client_dbus_bindings.h
	)
add_custom_target(comm_pkg_mgr_server_dbus_bindings.h
	COMMAND dbus-binding-tool --prefix=pkgmgr --mode=glib-server
			${CMAKE_CURRENT_SOURCE_DIR}/comm_pkg_mgr.xml 
			--output=${CMAKE_CURRENT_BINARY_DIR}/comm_pkg_mgr_server_dbus_bindings.h
	)

#GDBUS specific code
add_custom_command(OUTPUT comm_pkg_mgr_client_gdbus_generated.c comm_pkg_mgr_client_gdbus_generated.h
	COMMAND gdbus-codegen --generate-c-code comm_pkg_mgr_client_gdbus_generated
			--interface-prefix pkgmgr ${CMAKE_CURRENT_SOURCE_DIR}/comm_pkg_mgr.xml
	)

# comm_status_broadcast : status broadcast interface (client - backend process)
add_custom_target(comm_status_broadcast_client_dbus_bindings.h
	COMMAND dbus-binding-tool --prefix=status_broadcast --mode=glib-client 
			${CMAKE_CURRENT_SOURCE_DIR}/comm_status_broadcast.xml 
			--output=${CMAKE_CURRENT_BINARY_DIR}/comm_status_broadcast_client_dbus_bindings.h
	)
add_custom_target(comm_status_broadcast_server_dbus_bindings.h
	COMMAND dbus-binding-tool --prefix=status_broadcast --mode=glib-server
			${CMAKE_CURRENT_SOURCE_DIR}/comm_status_broadcast.xml 
			--output=${CMAKE_CURRENT_BINARY_DIR}/comm_status_broadcast_server_dbus_bindings.h
	)

### Create marshaller header/source for signal (client must use this)
add_custom_target(comm_status_broadcast_signal_marshaller.h
		COMMAND glib-genmarshal --header ${CMAKE_CURRENT_SOURCE_DIR}/comm_status_broadcast_signal_marshaller.list > ${CMAKE_CURRENT_BINARY_DIR}/comm_status_broadcast_signal_marshaller.h
		)
add_custom_target(comm_status_broadcast_signal_marshaller.c
		COMMAND glib-genmarshal --body ${CMAKE_CURRENT_SOURCE_DIR}/comm_status_broadcast_signal_marshaller.list > ${CMAKE_CURRENT_BINARY_DIR}/comm_status_broadcast_signal_marshaller.c
		)
set_source_files_properties(comm_status_broadcast_signal_marshaller.c PROPERTIES GENERATED true)  # This source is generated during build time, so this property must be set





### Build modules

## client for apps
# Send request, get status signal
add_library(pkgmgr_installer_client SHARED
		comm_client_gdbus.c
		comm_pkg_mgr_client_gdbus_generated.c
		#${CMAKE_CURRENT_BINARY_DIR}/comm_status_broadcast_signal_marshaller.c
		)
set_target_properties(pkgmgr_installer_client PROPERTIES SOVERSION ${VERSION_MAJOR})
set_target_properties(pkgmgr_installer_client PROPERTIES VERSION ${VERSION})
set_target_properties(pkgmgr_installer_client PROPERTIES COMPILE_FLAGS "${comm_pkgs_CFLAGS_str}")
target_link_libraries(pkgmgr_installer_client ${comm_pkgs_LDFLAGS})
#add_dependencies(pkgmgr_installer_client comm_pkg_mgr_client_dbus_bindings.h comm_status_broadcast_client_dbus_bindings.h comm_status_broadcast_signal_marshaller.h comm_status_broadcast_signal_marshaller.c)
add_dependencies(pkgmgr_installer_client comm_pkg_mgr_client_gdbus_generated.h comm_pkg_mgr_client_gdbus_generated.c)

## pkg-mgr server for PMS
# Get request
add_library(pkgmgr_installer_pkg_mgr_server STATIC
		comm_pkg_mgr_server.c)
set_target_properties(pkgmgr_installer_pkg_mgr_server PROPERTIES SOVERSION ${VERSION_MAJOR})
set_target_properties(pkgmgr_installer_pkg_mgr_server PROPERTIES VERSION ${VERSION})
set_target_properties(pkgmgr_installer_pkg_mgr_server PROPERTIES COMPILE_FLAGS "${comm_pkgs_CFLAGS_str}")
target_link_libraries(pkgmgr_installer_pkg_mgr_server ${comm_pkgs_LDFLAGS})
add_dependencies(pkgmgr_installer_pkg_mgr_server comm_pkg_mgr_server_dbus_bindings.h)

## status-broadcast server for backend/downloader
# Send signal
add_library(pkgmgr_installer_status_broadcast_server SHARED
		comm_status_broadcast_server_dbus.c
	)
set_target_properties(pkgmgr_installer_status_broadcast_server PROPERTIES SOVERSION ${VERSION_MAJOR})
set_target_properties(pkgmgr_installer_status_broadcast_server PROPERTIES VERSION ${VERSION})
set_target_properties(pkgmgr_installer_status_broadcast_server PROPERTIES COMPILE_FLAGS "${comm_pkgs_CFLAGS_str}")
target_link_libraries(pkgmgr_installer_status_broadcast_server ${comm_pkgs_LDFLAGS})
add_dependencies(pkgmgr_installer_status_broadcast_server comm_status_broadcast_server_dbus_bindings.h)


## comm_socket
# Internal lib
add_library(comm_socket STATIC comm_socket.c)
set_target_properties(comm_socket PROPERTIES COMPILE_FLAGS "${comm_pkgs_CFLAGS_str}")
#target_link_libraries(comm_socket)

## pkgmgr_installer object (by youmin.ha)
# This library is for installer backend
add_library(pkgmgr_installer SHARED pkgmgr_installer.c)
set_target_properties(pkgmgr_installer PROPERTIES SOVERSION ${VERSION_MAJOR})
set_target_properties(pkgmgr_installer PROPERTIES VERSION ${VERSION})
set_target_properties(pkgmgr_installer PROPERTIES COMPILE_FLAGS "${comm_pkgs_CFLAGS_str}")
target_link_libraries(pkgmgr_installer pkgmgr_installer_status_broadcast_server ${comm_pkgs_LDFLAGS})


### Create pc file
configure_file(pkgmgr-installer-client.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer-client.pc @ONLY)
configure_file(pkgmgr-installer-status-broadcast-server.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer-status-broadcast-server.pc @ONLY)
configure_file(pkgmgr-installer.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer.pc @ONLY)


## Install
INSTALL(TARGETS 
			pkgmgr_installer_client 
			pkgmgr_installer_status_broadcast_server
			pkgmgr_installer
            DESTINATION ${LIB_INSTALL_DIR}
		COMPONENT RuntimeLibraries)
INSTALL(FILES 
			comm_client.h 
			comm_status_broadcast_server.h
			comm_config.h
			pkgmgr_installer.h
		DESTINATION include/pkgmgr)


INSTALL(FILES 
		${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer-client.pc 
		${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer-status-broadcast-server.pc 
		${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-installer.pc 
        DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)




## test
add_subdirectory(test)


