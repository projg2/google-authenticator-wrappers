cmake_minimum_required(VERSION 3.0)

project(google-authenticator-wrappers
	VERSION 1
	LANGUAGES)

# pre-set to silence warning, we do not use it anyway
set(CMAKE_INSTALL_LIBDIR "lib")
include(GNUInstallDirs)

set(CMAKE_INSTALL_PAMDIR "/etc/pam.d"
	CACHE PATH "Install path for pam.d files")

install(
	PROGRAMS
		bin/disable-2fa
		bin/enable-2fa-custom
		bin/enable-2fa-totp
	DESTINATION ${CMAKE_INSTALL_BINDIR})

install(
	FILES
		pam.d/google-auth
	DESTINATION ${CMAKE_INSTALL_PAMDIR})
