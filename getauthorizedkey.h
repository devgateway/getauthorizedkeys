#define RESULT_SUCCESS 0
#define RESULT_FAIL 1
#define RESULT_NONE 2

#ifndef CONFIG_FILE
#define CONFIG_FILE "/etc/getauthorizedkey.ini"
#endif

typedef struct {
	char *binddn;
	struct berval cred;
	int version;
} config;

typedef enum {
	CFG_LDAP_URI,
	CFG_LDAP_DN,
	CFG_LDAP_PW,
	CFG_USR_BASE,
	CFG_USR_SCOPE,
	CFG_USR_FILT
} cfg_index;

extern char *ldap_escape_filter(const char *string);

int get_pub_key(const char *username, config *cfg, char **keys);
int read_config();
