cmake_minimum_required(VERSION 3.0)

project(google-authenticator-wrappers
	VERSION 1
	LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_INSTALL_PAMDIR "/etc/pam.d"
	CACHE PATH "Install path for pam.d files")
set(CMAKE_INSTALL_GAUTH_STATEDIR "/var/lib/gauth"
	CACHE PATH "Storage path for gauth user configs")
GNUInstallDirs_get_absolute_install_dir(
	CMAKE_INSTALL_FULL_GAUTH_STATEDIR CMAKE_INSTALL_GAUTH_STATEDIR)

set(GAUTH_USERNAME "root"
	CACHE STRING "User owning gauth state files")

configure_file(pam.d/gauth.in pam.d/gauth @ONLY)
add_definitions(
	-DVERSION=\"${PROJECT_VERSION}\"
	-DGAUTH_STATEDIR=\"${CMAKE_INSTALL_FULL_GAUTH_STATEDIR}\")

add_executable(gauthctl
	src/gauthctl.c)
target_link_libraries(gauthctl pam pam_misc)

add_executable(gauth-test
	src/gauth-test.c)
target_link_libraries(gauth-test pam pam_misc)

install(
	PROGRAMS
		bin/disable-2fa
		bin/enable-2fa-custom
		bin/enable-2fa-totp
	DESTINATION ${CMAKE_INSTALL_BINDIR})

install(
	TARGETS
		gauthctl
		gauth-test
	PERMISSIONS
		OWNER_READ OWNER_WRITE OWNER_EXECUTE
		GROUP_EXECUTE WORLD_EXECUTE SETUID
	DESTINATION ${CMAKE_INSTALL_BINDIR})

install(
	FILES
		pam.d/gauthctl
		${CMAKE_BINARY_DIR}/pam.d/gauth
	DESTINATION ${CMAKE_INSTALL_PAMDIR})

install(CODE "
	file(MAKE_DIRECTORY gauth.tmp)
	file(WRITE gauth.tmp/.keep \"\")

	file(INSTALL gauth.tmp/.
		DESTINATION \"${CMAKE_INSTALL_GAUTH_STATEDIR}\"
		DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

	file(REMOVE_RECURSE gauth.tmp)")
