#ifndef SUDO_JWT_COMMON_H
#define SUDO_JWT_COMMON_H

#include <sudo_plugin.h>

#define SUDO_AWESOME_JWT_POLICY "sudo-awesome-jwt:policy"
#define SUDO_AWESOME_JWT_APPROVAL "sudo-awesome-jwt:approval"
#define SUDO_AWESOME_JWT_NAME "sudo-awesome-jwt"
#define DEFAULT_CONFIG_PATH "/usr/local/etc/sudo_awesome_jwt.conf"
#define DEFAULT_SCOPE "sudo"
#define SUDO_AWESOME_JWT_VERSION "0.1.0"
#define SUDO_AWESOME_JWT_FLAVOR "C"
#define SUDO_AWESOME_JWT_RUNAS_USER_DEFAULT "root"
#define SUDO_AWESOME_JWT_RUNAS_UID_DEFAULT 0
#define SUDO_AWESOME_JWT_RUNAS_GID_DEFAULT 0
#define MAX_TOKEN_BYTES 16384
#define CLOCK_SKEW_SECONDS 60
#define MAX_AUDIENCE_BYTES 1024
#define MAX_ALLOWLIST_BYTES 4096

int jwt_common_open(unsigned int version, sudo_printf_t sudo_plugin_printf,
                    char * const user_info[], char * const plugin_options[],
                    const char **errstr);
void jwt_common_close(void);
int jwt_common_check(char * const command_info[], char * const run_argv[],
                     const char **errstr, const char *log_prefix);
int jwt_common_show_version(int verbose, const char *label);
void jwt_common_parse_debug_options(char * const plugin_options[]);
void jwt_common_debug(const char *fmt, ...);

#endif
