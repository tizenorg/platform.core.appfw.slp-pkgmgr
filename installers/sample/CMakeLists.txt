include(FindPkgConfig)
pkg_check_modules(security_pkgs security-server)

add_executable(pkgmgr_backend_sample
	sample_backend.c)
target_link_libraries(pkgmgr_backend_sample pkgmgr_installer)

add_library(pkgmgr_backend_lib_sample SHARED
	sample_backendlib.c)

install(TARGETS pkgmgr_backend_sample
	DESTINATION bin
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

install(TARGETS pkgmgr_backend_lib_sample 
	DESTINATION lib 
	COMPONENT RuntimeLibraries 
	PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
