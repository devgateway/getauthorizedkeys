/* Copyright 2016-2017 Development Gateway, Inc
 * This file is part of getauthorizedkeys, see COPYING */
#include <stdlib.h>
#include <stdio.h>

#include "getauthorizedkeys.h"

#define RESULT_SUCCESS 0
#define RESULT_FAIL 1
#define RESULT_NONE 2

int main(int argc, const char *argv[]) {
	char *username, **keys;
	int result = RESULT_FAIL, n, i;

	openlog(NULL, 0, LOG_AUTH);

	/* get the argument */
	if (argc == 2) {
		username = ldap_escape_filter(argv[1]);
	} else {
		syslog(LOG_CRIT, "Expected 1 argument, got %i", argc);
		return RESULT_FAIL;
	}

	/* receive and print the keys */
	n = get_pub_keys(username, &keys);
	if (n == -1) {
		goto end;
	} else {
		for (i = 0; i < n; i++) {
			puts(keys[i]);
			free(keys[i]);
		}
		if (keys) free(keys);
		result = n ? RESULT_SUCCESS : RESULT_NONE;
	}

end:
	free(username);
	return result;
}
