#include <sudo_plugin.h>

#include "sudo_jwt_common.h"
#include "sudo_jwt_approval.h"

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

    return jwt_common_open(version, sudo_plugin_printf, user_info, plugin_options, errstr);
}

static void approval_close(void) {
    jwt_common_close();
}

static int approval_check(char * const command_info[], char * const run_argv[],
                          char * const run_envp[], const char **errstr) {
    (void)run_envp;
    return jwt_common_check(command_info, run_argv, errstr, SUDO_AWESOME_JWT_APPROVAL);
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
