# Copyright 2016 Development Gateway, Inc
cmake_minimum_required(VERSION 2.8.11)
project(getauthorizedkey C)

set(SBINDIR /usr/sbin CACHE PATH "Privileged user binary path")

add_executable(getauthorizedkey getauthorizedkey.c)
target_link_libraries(ldap)

install(TARGETS getauthorizedkey
	RUNTIME DESTINATION "${SBINDIR}")
