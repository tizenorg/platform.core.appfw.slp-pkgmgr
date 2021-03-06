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
pkg_check_modules(parser_pkgs REQUIRED dlog libxml-2.0 glib-2.0 sqlite3 db-util)

foreach(flag ${parser_pkgs_CFLAGS})
	set(parser_pkgs_CFLAGS_str "${parser_pkgs_CFLAGS_str} ${flag}")
endforeach()

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

### Set current binary dir to be included (for generated *.h files)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR}/client/include)

### Build modules

## pkgmgr_parser object (by sewook.park)
# This library is for installer backend
add_library(pkgmgr_parser SHARED pkgmgr_parser.c pkgmgr_parser_db.c)
#add_library(pkgmgr_parser SHARED pkgmgr_parser.c)
set_target_properties(pkgmgr_parser PROPERTIES SOVERSION ${VERSION_MAJOR})
set_target_properties(pkgmgr_parser PROPERTIES VERSION ${VERSION})
set_target_properties(pkgmgr_parser PROPERTIES COMPILE_FLAGS "${parser_pkgs_CFLAGS_str}")
target_link_libraries(pkgmgr_parser ${parser_pkgs_LDFLAGS})

### Create pc file
configure_file(pkgmgr-parser.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-parser.pc @ONLY)
configure_file(preload_list.txt.in preload_list.txt @ONLY)
configure_file(manifest.xsd.in manifest.xsd @ONLY)
configure_file(xml.xsd.in xml.xsd @ONLY)

## Install
INSTALL(TARGETS
			pkgmgr_parser
		DESTINATION lib
		COMPONENT RuntimeLibraries)
INSTALL(FILES
			pkgmgr_parser.h
		DESTINATION include/pkgmgr)

INSTALL(FILES
		${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-parser.pc
		DESTINATION lib/pkgconfig)

INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/preload_list.txt DESTINATION ${PREFIX}/etc/package-manager/preload/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/manifest.xsd DESTINATION ${PREFIX}/etc/package-manager/preload/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/xml.xsd DESTINATION ${PREFIX}/etc/package-manager/preload/)
