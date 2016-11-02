# Copyright 2016 Development Gateway, Inc
cmake_minimum_required(VERSION 2.8.11)
project(getauthorizedkey C)

set(SBINDIR /usr/sbin CACHE PATH "Privileged user binary path")

add_subdirectory(ldapescape)

add_library(inih STATIC inih/ini.c)
target_compile_definitions(inih PRIVATE INI_MAX_LINE=512)
set_target_properties(inih PROPERTIES POSITION_INDEPENDENT_CODE true)

add_executable(getauthorizedkey getauthorizedkey.c config.c)
target_link_libraries(getauthorizedkey ldap ldapescape inih)

install(TARGETS getauthorizedkey
	RUNTIME DESTINATION "${SBINDIR}")
