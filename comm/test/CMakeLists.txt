include(FindPkgConfig)
pkg_check_modules(test_pkgs REQUIRED dbus-glib-1 glib-2.0 dlog)

add_definitions(${test_pkgs_CFLAGS})


add_executable(test_comm_pkg_mgr_server
	test_comm_pkg_mgr_server.c)
target_link_libraries(test_comm_pkg_mgr_server pkgmgr_installer_pkg_mgr_server)
target_link_libraries(test_comm_pkg_mgr_server ${test_pkgs_LDFLAGS})

add_executable(test_comm_status_broadcast_server
	test_comm_status_broadcast_server.c)
target_link_libraries(test_comm_status_broadcast_server pkgmgr_installer_status_broadcast_server)
target_link_libraries(test_comm_status_broadcast_server ${test_pkgs_LDFLAGS})

add_executable(test_comm_client
	test_comm_client.c)
target_link_libraries(test_comm_client pkgmgr_installer_client)
target_link_libraries(test_comm_client ${test_pkgs_LDFLAGS})


add_executable(test_comm_socket
		test_comm_socket.c)
target_link_libraries(test_comm_socket comm_socket ${test_pkgs_LDFLAGS})
set_target_properties(test_comm_socket PROPERTIES SKIP_BUILD_RPATH true)


add_executable(test_pkgmgr_installer
		test_pkgmgr_installer.c)
target_link_libraries(test_pkgmgr_installer pkgmgr_installer pkgmgr_installer_client ${test_pkgs_LDFLAGS})
set_target_properties(test_pkgmgr_installer PROPERTIES SKIP_BUILD_RPATH true)

