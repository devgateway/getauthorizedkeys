# Copyright 2016 Development Gateway, Inc
cmake_minimum_required(VERSION 2.8.11)
project(getauthorizedkeys C)

set(LIBEXEC /usr/libexec CACHE PATH "Helper executable path")
set(CONFIGFILE /etc/getauthorizedkeys.ini CACHE FILE "Configuration file")

add_subdirectory(ldapescape)

add_library(inih STATIC inih/ini.c)
target_compile_definitions(inih PRIVATE INI_MAX_LINE=512)
set_target_properties(inih PROPERTIES POSITION_INDEPENDENT_CODE true)

file(GLOB SOURCES *.c)
add_executable(getauthorizedkeys ${SOURCES})
target_compile_definitions(getauthorizedkeys PRIVATE CONFIG_FILE="${CONFIGFILE}")
target_link_libraries(getauthorizedkeys ldap ldapescape inih)

install(TARGETS getauthorizedkeys
	RUNTIME DESTINATION "${LIBEXEC}")

add_subdirectory(man)
