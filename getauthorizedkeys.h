#include <syslog.h>

#ifndef CONFIG_FILE
#define CONFIG_FILE "/etc/getauthorizedkeys.ini"
#endif

typedef enum {
	CFG_LDAP_URI,
	CFG_LDAP_DN,
	CFG_LDAP_PW,
	CFG_USR_BASE,
	CFG_USR_SCOPE,
	CFG_USR_FILT,
	CFG_USR_ATTR
} cfg_index;

extern char *ldap_escape_filter(const char *string);

int read_config();
int get_pub_keys(const char *raw_username, char ***keys);
