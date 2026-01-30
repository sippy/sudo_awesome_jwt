#include <pwd.h>
#include <stddef.h>
#include <sudo_plugin.h>

#include "sudo_jwt_common.h"
#include "sudo_jwt_policy.h"

static int policy_open(unsigned int version, sudo_conv_t conversation,
                       sudo_printf_t sudo_plugin_printf, char * const settings[],
                       char * const user_info[], char * const user_env[],
                       char * const plugin_options[], const char **errstr) {
    (void)conversation;
    (void)settings;
    (void)user_env;

    return jwt_common_open(version, sudo_plugin_printf, user_info, plugin_options, errstr);
}

static void policy_close(int exit_status, int error) {
    (void)exit_status;
    (void)error;
    jwt_common_close();
}

static int policy_show_version(int verbose) {
    return jwt_common_show_version(verbose, "sudo-awesome-jwt-policy");
}

static int policy_check(int argc, char * const argv[], char *env_add[],
                        char **command_info[], char **argv_out[],
                        char **user_env_out[], const char **errstr) {
    (void)argc;
    (void)env_add;

    if (command_info) {
        *command_info = NULL;
    }
    if (argv_out) {
        *argv_out = (char **)argv;
    }
    if (user_env_out) {
        *user_env_out = NULL;
    }

    return jwt_common_check(NULL, argv, errstr, "sudo-awesome-jwt-policy");
}

static int policy_list(int argc, char * const argv[], int verbose, const char *user, const char **errstr) {
    (void)argc;
    (void)argv;
    (void)user;
    (void)errstr;

    return jwt_common_show_version(verbose, "sudo-awesome-jwt-policy");
}

static int policy_validate(const char **errstr) {
    (void)errstr;
    return 1;
}

static void policy_invalidate(int rmcred) {
    (void)rmcred;
}

static int policy_init_session(struct passwd *pwd, char **user_env_out[], const char **errstr) {
    (void)pwd;
    (void)user_env_out;
    (void)errstr;
    return 1;
}

__attribute__((visibility("default"))) struct policy_plugin policy = {
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    policy_open,
    policy_close,
    policy_show_version,
    policy_check,
    policy_list,
    policy_validate,
    policy_invalidate,
    policy_init_session,
    NULL,
    NULL,
    NULL
};

__attribute__((visibility("default"))) struct policy_plugin sudoers_policy = {
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    policy_open,
    policy_close,
    policy_show_version,
    policy_check,
    policy_list,
    policy_validate,
    policy_invalidate,
    policy_init_session,
    NULL,
    NULL,
    NULL
};
