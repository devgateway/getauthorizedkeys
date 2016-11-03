# Copyright 2016 Development Gateway, Inc
cmake_minimum_required(VERSION 2.8.11)
project(getauthorizedkey C)

set(LIBEXEC /usr/libexec CACHE PATH "Helper executable path")

add_subdirectory(ldapescape)

add_library(inih STATIC inih/ini.c)
target_compile_definitions(inih PRIVATE INI_MAX_LINE=512)
set_target_properties(inih PROPERTIES POSITION_INDEPENDENT_CODE true)

file(GLOB sources *.c)
add_executable(getauthorizedkey ${sources})
target_link_libraries(getauthorizedkey ldap ldapescape inih)

install(TARGETS getauthorizedkey
	RUNTIME DESTINATION "${LIBEXEC}")
