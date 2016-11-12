#include <stdlib.h>
#include <stdio.h>

#include "getauthorizedkeys.h"

int main(int argc, const char *argv[]) {
	char *username, **keys;
	int result = RESULT_FAIL, n, i;

	openlog(NULL, 0, LOG_AUTH);

	if (argc == 2) {
		username = ldap_escape_filter(argv[1]);
	} else {
		syslog(LOG_CRIT, "Expected 1 argument, got %i", argc);
		return RESULT_FAIL;
	}

	n = get_pub_keys(username, &keys);
	if (n == -1) {
		goto end;
	} else {
		for (i = 0; i < n; i++) {
			puts(keys[i]);
			free(keys[i]);
		}
		free(keys);
		result = n ? RESULT_SUCCESS : RESULT_NONE;
	}

end:
	free(username);
	return result;
}
