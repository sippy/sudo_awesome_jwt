#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sudo_plugin.h>

#include "sudo_jwt_common.h"
#include "sudo_jwt_policy.h"

static int policy_debug_enabled(void) {
    const char *dbg = getenv("SUDO_AWESOME_JWT_DEBUG");
    return (dbg && *dbg && strcmp(dbg, "0") != 0);
}

static void policy_debug(const char *msg) {
    if (policy_debug_enabled()) {
        fprintf(stderr, "sudo-awesome-jwt-policy: %s\n", msg);
    }
}

static int policy_open(unsigned int version, sudo_conv_t conversation,
                       sudo_printf_t sudo_plugin_printf, char * const settings[],
                       char * const user_info[], char * const user_env[],
                       char * const plugin_options[], const char **errstr) {
    (void)conversation;
    (void)settings;
    (void)user_env;

    policy_debug("policy_open");
    int rc = jwt_common_open(version, sudo_plugin_printf, user_info, plugin_options, errstr);
    if (rc != 1 && errstr && *errstr) {
        if (policy_debug_enabled()) {
            fprintf(stderr, "sudo-awesome-jwt-policy: %s\n", *errstr);
        }
    }
    return rc;
}

static void policy_close(int exit_status, int error) {
    (void)exit_status;
    (void)error;
    policy_debug("policy_close");
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

    policy_debug("policy_check");
    if (command_info) {
        *command_info = NULL;
    }
    if (argv_out) {
        *argv_out = (char **)argv;
    }
    if (user_env_out) {
        *user_env_out = NULL;
    }

    int rc = jwt_common_check(NULL, argv, errstr, "sudo-awesome-jwt-policy");
    if (policy_debug_enabled()) {
        fprintf(stderr, "sudo-awesome-jwt-policy: policy_check rc=%d\n", rc);
    }
    if (rc != 1 && errstr && *errstr) {
        if (policy_debug_enabled()) {
            fprintf(stderr, "sudo-awesome-jwt-policy: %s\n", *errstr);
        }
    }
    return rc;
}

static int policy_list(int argc, char * const argv[], int verbose, const char *user, const char **errstr) {
    (void)argc;
    (void)argv;
    (void)user;
    (void)errstr;

    policy_debug("policy_list");
    return jwt_common_show_version(verbose, "sudo-awesome-jwt-policy");
}

static int policy_validate(const char **errstr) {
    (void)errstr;
    policy_debug("policy_validate");
    return 1;
}

static void policy_invalidate(int rmcred) {
    (void)rmcred;
    policy_debug("policy_invalidate");
}

static int policy_init_session(struct passwd *pwd, char **user_env_out[], const char **errstr) {
    (void)pwd;
    (void)user_env_out;
    (void)errstr;
    policy_debug("policy_init_session");
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
