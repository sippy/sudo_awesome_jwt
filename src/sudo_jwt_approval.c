#include <stddef.h>
#include <string.h>
#include <sudo_plugin.h>

#include "sudo_jwt_common.h"
#include "sudo_jwt_approval.h"

static int submit_setenv_requested(int submit_optind, char * const submit_argv[]) {
    if (!submit_argv || submit_optind <= 0) {
        return 0;
    }
    for (int i = 1; i < submit_optind && submit_argv[i]; i++) {
        const char *arg = submit_argv[i];
        if (!arg) {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            break;
        }
        if (strcmp(arg, "-E") == 0) {
            return 1;
        }
        if (strncmp(arg, "--preserve-env", 14) == 0) {
            return 1;
        }
        if (arg[0] == '-' && arg[1] != '\0' && arg[1] != '-') {
            if (strchr(arg + 1, 'E') != NULL) {
                return 1;
            }
        }
    }
    return 0;
}

static int approval_open(unsigned int version, sudo_conv_t conversation,
                         sudo_printf_t sudo_plugin_printf, char * const settings[],
                         char * const user_info[], int submit_optind,
                         char * const submit_argv[], char * const submit_envp[],
                         char * const plugin_options[], const char **errstr) {
    (void)conversation;
    (void)settings;
    (void)submit_optind;
    (void)submit_argv;
    (void)submit_envp;

    int setenv = submit_setenv_requested(submit_optind, submit_argv);
    int rc = jwt_common_open(version, sudo_plugin_printf, user_info, plugin_options, errstr);
    if (rc > 0) {
        jwt_common_set_setenv_requested(setenv);
    }
    return rc;
}

static void approval_close(void) {
    jwt_common_close();
}

static int approval_check(char * const command_info[], char * const run_argv[],
                          char * const run_envp[], const char **errstr) {
    jwt_common_set_run_envp(run_envp);
    int rc = jwt_common_check(command_info, run_argv, errstr, SUDO_AWESOME_JWT_APPROVAL);
    jwt_common_set_run_envp(NULL);
    return rc;
}

static int approval_show_version(int verbose) {
    return jwt_common_show_version(verbose, "Approval");
}

__attribute__((visibility("default"))) struct approval_plugin approval = {
    SUDO_APPROVAL_PLUGIN,
    SUDO_API_VERSION,
    approval_open,
    approval_close,
    approval_check,
    approval_show_version
};
