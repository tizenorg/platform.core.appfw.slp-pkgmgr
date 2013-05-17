
CONFIGURE_FILE(pkgmgr-types.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-types.pc @ONLY)

INSTALL(FILES 
			${CMAKE_CURRENT_SOURCE_DIR}/include/package-manager-types.h
			${CMAKE_CURRENT_SOURCE_DIR}/include/package-manager-plugin.h
		DESTINATION include)
		
    INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgmgr-types.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
