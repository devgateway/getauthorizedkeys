#include <stdlib.h>
#include <stdio.h>
#include <ldap.h>
#include <syslog.h>
#include <errno.h>

#include "getauthorizedkey.h"

static inline LDAP *ldap_connect();

extern char *cfg[];

int get_pub_keys(const char *raw_username, char **keys) {
	LDAP *ldap;
	char *username = NULL, *filter = NULL;

	username = ldap_escape_filter(raw_username);
	if (!username) {
		syslog(LOG_CRIT, "Unable to read config");
		return -1;
	}

	n = asprintf(&filter, cfg[CFG_USR_FILT], username);
	if (n == -1) {
		filter = NULL;
		result = -1;
		goto end;
	}

	ldap = ldap_connect();
	if (!ldap) return -1;

end:
	free(username);
	if (filter) free(filter);
	return result;
}

/* Connect and bind to LDAP.
Returns: LDAP handle or NULL */
static inline LDAP *ldap_connect() {
	int rc;
	LDAP *ldap = NULL;
	struct berval cred;
	const int version3 = LDAP_VERSION3;
	char *binddn;

	/* allocate LDAP structure */
	rc = ldap_initialize(&ldap, cfg[CFG_LDAP_URI]);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Unable to initialize LDAP library: %s", strerror(errno));
		return NULL;
	}

	/* request LDAPv3 */
	rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version3);
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_ERR, "Unable to request LDAP protocol");
		return NULL;
	}

	binddn =      *(char *) cfg[CFG_LDAP_DN] ? cfg[CFG_LDAP_DN] : NULL;
	cred.bv_val = *(char *) cfg[CFG_LDAP_PW] ? cfg[CFG_LDAP_PW] : NULL;
	cred.bv_len = cred.bv_val ? strlen(cred.bv_val) : 0;

	/* connect to LDAP server and bind */
	rc = ldap_sasl_bind_s(ldap, cfg->binddn, LDAP_SASL_SIMPLE, &cfg->cred,
			NULL, NULL, NULL);
	if (rc == LDAP_SUCCESS) {
		return ldap;
	} else {
		syslog(LOG_ERR, "Unable to bind to LDAP: %s", ldap_err2string(rc));
		return NULL;
	}
}

int main(int argc, const char *argv[]) {
	char *username, keys[];
	LDAP *ldap;
	int result = RESULT_FAIL, n, i;

	openlog(NULL, 0, LOG_AUTH);

	if (argc == 2) {
		username = ldap_escape_filter(argv[1]);
	} else {
		syslog(LOG_CRIT, "Expected 1 argument, got %i", argc);
		return RESULT_FAIL;
	}

	if (!read_config()) goto end;

	n = get_pub_keys(username, &keys);
	if (n == -1) {
		goto end;
	} else {
		for (i = 0; i < n; i++) {
			puts(keys[i]);
		}
		result = n ? RESULT_SUCCESS : RESULT_NONE;
	}

end:
	free(username);
	return result;
}
