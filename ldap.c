#include <ldap.h>
#include <errno.h>

#include "getauthorizedkey.h"

static inline int get_scope(const char *scope_str);
static inline LDAP *ldap_connect();

extern char *cfg[];

int get_pub_keys(const char *raw_username, char **keys) {
	LDAP *ldap;
	LDAPMessage *res = NULL;
	char *username = NULL, *filter = NULL;
	int rc, i, scope, result;

	if (!read_config()) return -1;

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

	rc = ldap_search_ext_s(ldap, base, scope, filter, attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Search '%s' failed: %s", filter, ldap_err2string(rc));
		goto end;
	}

end:
	free(username);
	if (filter) free(filter);
	if (res) ldap_msgfree(res);
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

