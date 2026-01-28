#ifndef SUDO_JWT_COMMON_H
#define SUDO_JWT_COMMON_H

#include <sudo_plugin.h>

int jwt_common_open(unsigned int version, sudo_printf_t sudo_plugin_printf,
                    char * const user_info[], char * const plugin_options[],
                    const char **errstr);
void jwt_common_close(void);
int jwt_common_check(char * const command_info[], char * const run_argv[],
                     const char **errstr, const char *log_prefix);
int jwt_common_show_version(int verbose, const char *label);

#endif
