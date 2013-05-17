include(FindPkgConfig)
pkg_check_modules(parser_pkgs REQUIRED dlog libxml-2.0)

foreach(flag ${parser_pkgs_CFLAGS})
        set(parser_pkgs_CFLAGS_str "${parser_pkgs_CFLAGS_str} ${flag}")
endforeach()

add_executable(pkgmgr_backend_sample
	sample_backend.c)
target_link_libraries(pkgmgr_backend_sample pkgmgr_installer)

add_library(pkgmgr_backend_lib_sample SHARED
	sample_backendlib.c)

add_library(pkgmgr_parser_lib_sample SHARED
	sample_parserlib.c)
set_target_properties(pkgmgr_parser_lib_sample PROPERTIES COMPILE_FLAGS "${parser_pkgs_CFLAGS_str}")
target_link_libraries(pkgmgr_parser_lib_sample ${parser_pkgs_LDFLAGS})

install(TARGETS pkgmgr_backend_sample
	DESTINATION bin
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

install(TARGETS pkgmgr_backend_lib_sample 
    DESTINATION ${LIB_INSTALL_DIR}
	COMPONENT RuntimeLibraries 
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

install(TARGETS pkgmgr_parser_lib_sample
    DESTINATION ${LIB_INSTALL_DIR}
	COMPONENT RuntimeLibraries
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
