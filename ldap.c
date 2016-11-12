#define _GNU_SOURCE
#include <stdio.h>
#include <ldap.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "getauthorizedkeys.h"

static inline int get_scope(const char *scope_str);
static inline LDAP *ldap_connect();

extern char *cfg[];

int get_pub_keys(const char *raw_username, char ***pub_keys) {
	LDAP *ldap;
	LDAPMessage *res = NULL;
	LDAPMessage *first = NULL;
	char *username = NULL, *filter = NULL;
	struct berval **values;
	int rc, n, i, scope, result;
	char *attrs[] = {
		cfg[CFG_USR_ATTR],
		NULL
	};

	if (!read_config()) return -1;

	/* escape & interpolate the username */
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

	scope = get_scope(cfg[CFG_USR_SCOPE]);

	/* connect & bind to LDAP server */
	ldap = ldap_connect();
	if (!ldap) return -1;

	/* run the search */
	rc = ldap_search_ext_s(ldap, cfg[CFG_USR_BASE], scope, filter, attrs,
			0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Search '%s' failed: %s", filter, ldap_err2string(rc));
		goto end;
	}

	n = ldap_count_entries(ldap, res);
	switch (n) {
		case -1:
		case 0:
			result = 0;
			*pub_keys = NULL;
			syslog(LOG_ERR, "Search '%s' found no entries", filter);
			goto end;
		case 1:
			first = ldap_first_entry(ldap, res);
			values = ldap_get_values_len(ldap, first, cfg[CFG_USR_ATTR]);
			result = ldap_count_values_len(values);
			*pub_keys = (char **) malloc(result * sizeof(char **));
			for (i = 0; i < result; i++) {
				(*pub_keys)[i] = strndup(values[i]->bv_val, values[i]->bv_len);
			}
			ldap_value_free_len(values);
			break;
		default:
			syslog(LOG_WARNING, "Search '%s' found %i entries, assuming failure",
					filter, n);
	}

end:
	free(username);
	if (filter) free(filter);
	if (res) ldap_msgfree(res);
	ldap_unbind_ext_s(ldap, NULL, NULL);
	return result;
}

/* Convert scope keyword string to numeric value.
Args:
	scope_str - scope keyword
Returns:
	numeric scope for LDAP library */
static inline int get_scope(const char *scope_str) {
	typedef struct {
		const char *kw;
		const int val;
	} scope_type;
	static scope_type scopes[] = {
		{"sub",  LDAP_SCOPE_SUB},
		{"one",  LDAP_SCOPE_ONE},
		{"base", LDAP_SCOPE_BASE}
	};
	const int n_scopes = sizeof(scopes) / sizeof(scopes[0]);
	int i;

	for (i = 0; i < n_scopes; i++) {
		if (strcasecmp(scope_str, scopes[i].kw) == 0) return scopes[i].val;
	}
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

	if (cfg[CFG_LDAP_DN]) {
		binddn = cfg[CFG_LDAP_DN][0] ? cfg[CFG_LDAP_DN] : NULL;
	} else {
		binddn = NULL;
	}
	if (cfg[CFG_LDAP_PW]) {
		cred.bv_val = cfg[CFG_LDAP_PW][0] ? cfg[CFG_LDAP_PW] : NULL;
	} else {
		cred.bv_val = NULL;
	}
	cred.bv_len = cred.bv_val ? strlen(cred.bv_val) : 0;

	/* connect to LDAP server and bind */
	rc = ldap_sasl_bind_s(ldap, binddn, LDAP_SASL_SIMPLE, &cred,
			NULL, NULL, NULL);
	if (rc == LDAP_SUCCESS) {
		return ldap;
	} else {
		syslog(LOG_ERR, "Unable to bind to LDAP: %s", ldap_err2string(rc));
		return NULL;
	}
}

