#include <string.h>

#include "inih/ini.h"
#include "getauthorizedkeys.h"

typedef struct {
	const char *section;
	const char *name;
	cfg_index index;
} cfg_line;

cfg_line cfg_lines[] = {
	{"ldap",       "uri",        CFG_LDAP_URI},
	{"ldap",       "binddn",     CFG_LDAP_DN},
	{"ldap",       "bindpw",     CFG_LDAP_PW},
	{"user",       "base",       CFG_USR_BASE},
	{"user",       "scope",      CFG_USR_SCOPE},
	{"user",       "filter",     CFG_USR_FILT},
	{"user",       "attr",       CFG_USR_ATTR}
};
char *cfg[sizeof(cfg_lines) / sizeof(cfg_lines[0])] = { NULL };

/* Callback for ini parser,
Args, returns: see ini.h */
static int ini_callback(void *user, const char *section, const char *name, const char *value) {
	int i, name_match, section_match;
	const size_t cfg_size = sizeof(cfg) / sizeof(cfg[0]);

	for (i = 0; i < cfg_size; i++) {
		name_match =    !strcmp(name,    cfg_lines[i].name);
		section_match = !strcmp(section, cfg_lines[i].section);
		if (name_match && section_match) cfg[cfg_lines[i].index] = strdup(value);
	}

	return 1;
}

/* Read INI config.
Returns: non-zero on success */
int read_config() {
	int fail, i;
	const size_t cfg_size = sizeof(cfg) / sizeof(cfg[0]);

	fail = ini_parse(CONFIG_FILE, ini_callback, NULL);
	if (fail) {
		syslog(LOG_CRIT, "Unable to parse ini file");
		goto end;
	}

	if (!cfg[CFG_USR_ATTR]) cfg[CFG_USR_ATTR] = "sshPublicKey";

	/* check for unset settings */
	for (i = 0; i < cfg_size; i++) {
		/* LDAP settings are optional: bind can be anonymous,
		 * URI can be taken from library global defaults */
		if ( !strcmp(cfg_lines[i].section, "ldap") ) continue;

		if ( !cfg[cfg_lines[i].index] ) {
			syslog(LOG_CRIT, CONFIG_FILE ": missing setting '%s' "
					"in section '%s'", cfg_lines[i].name, cfg_lines[i].section);
			return 0;
		}
	}

end:
	return !fail;
}
