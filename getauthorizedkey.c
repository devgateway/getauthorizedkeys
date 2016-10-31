#include <ldap.h>
#include <syslog.h>

#define SUCCESS 0
#define FAIL 1

typedef struct {
	char *binddn;
	struct berval cred;
	int version;
} config;

extern char *ldap_escape_filter(const char *string);

int getpubkey(char *uri, config *cfg, char **key) {
	int rc;
	LDAP *ldap = NULL;

	/* allocate LDAP structure */
	rc = ldap_initialize(&ldap, uri);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Unable to initialize LDAP library: %s", strerror(errno));
		return FAIL;
	}

	/* request LDAPv3 */
	rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &cfg->version);
	if (rc != LDAP_OPT_SUCCESS) {
		syslog(LOG_ERR, "Unable to request LDAP protocol");
		return FAIL;
	}

	/* connect to LDAP server and bind */
	rc = ldap_sasl_bind_s(ldap, binddn, LDAP_SASL_SIMPLE, &cfg->cred,
			NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Unable to bind to LDAP: %s", ldap_err2string(rc));
		return FAIL;
	}
}

int main(int argc, const char *argv[]) {
	config cfg;
	char *username;

	openlog(NULL, 0, LOG_AUTH);

	if (argc == 2) {
		username = ldap_escape_filter(argv[1]);
	} else {
		syslog(LOG_CRIT, "Expected 1 argument, got %i", argc);
		return FAIL;
	}

	cfg.binddn = NULL;
	cfg.cred.bv_val = NULL;
	cfg.cred.bv_len = 0;
	cfg.version = LDAP_VERSION3;

end:
	free(username);
}
