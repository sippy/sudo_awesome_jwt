#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sudo_plugin.h>

#include "sudo_jwt_common.h"
#include "sudo_jwt_policy.h"

static char **g_command_info;
static char **g_user_env;
static char **g_user_env_alloc;
static char **g_argv_out_alloc;
static char *g_env_empty[1];
static char *g_runas_user;
static uid_t g_runas_uid;
static gid_t g_runas_gid;
static int g_runas_uid_set;
static int g_runas_gid_set;

static void policy_debug(const char *msg) {
    jwt_common_debug("%s:%s\n", SUDO_AWESOME_JWT_POLICY, msg);
}

static void policy_debug_argv(char * const argv[]) {
    if (!argv) {
        jwt_common_debug("%s:argv_out dump: (null)\n", SUDO_AWESOME_JWT_POLICY);
        return;
    }
    jwt_common_debug("%s:argv_out dump:\n", SUDO_AWESOME_JWT_POLICY);
    for (size_t i = 0; argv[i]; i++) {
        jwt_common_debug("  [%zu] %s\n", i, argv[i]);
    }
}

static void free_command_info(char **info) {
    if (!info) {
        return;
    }
    for (size_t i = 0; info[i]; i++) {
        free(info[i]);
    }
    free(info);
}

static void free_user_env(char **env) {
    if (!env) {
        return;
    }
    for (size_t i = 0; env[i]; i++) {
        free(env[i]);
    }
    free(env);
}

static void free_argv_out(char **argv) {
    if (!argv) {
        return;
    }
    for (size_t i = 0; argv[i]; i++) {
        free(argv[i]);
    }
    free(argv);
}

static void reset_runas(void) {
    free(g_runas_user);
    g_runas_user = NULL;
    g_runas_uid_set = 0;
    g_runas_gid_set = 0;
}

static void parse_runas_settings(char * const settings[]) {
    reset_runas();
    if (!settings) {
        return;
    }
    for (size_t i = 0; settings[i]; i++) {
        const char *opt = settings[i];
        if (strncmp(opt, "runas_user=", 11) == 0) {
            const char *val = opt + 11;
            if (*val) {
                g_runas_user = strdup(val);
            }
        } else if (strncmp(opt, "runas_uid=", 10) == 0) {
            const char *val = opt + 10;
            char *endp = NULL;
            errno = 0;
            unsigned long parsed = strtoul(val, &endp, 10);
            if (errno == 0 && endp && *endp == '\0') {
                g_runas_uid = (uid_t)parsed;
                g_runas_uid_set = 1;
            }
        } else if (strncmp(opt, "runas_gid=", 10) == 0) {
            const char *val = opt + 10;
            char *endp = NULL;
            errno = 0;
            unsigned long parsed = strtoul(val, &endp, 10);
            if (errno == 0 && endp && *endp == '\0') {
                g_runas_gid = (gid_t)parsed;
                g_runas_gid_set = 1;
            }
        }
    }
}

static void fill_runas_from_user(void) {
    if (!g_runas_user || (g_runas_uid_set && g_runas_gid_set)) {
        return;
    }
    struct passwd *pw = getpwnam(g_runas_user);
    if (!pw) {
        return;
    }
    if (!g_runas_uid_set) {
        g_runas_uid = pw->pw_uid;
        g_runas_uid_set = 1;
    }
    if (!g_runas_gid_set) {
        g_runas_gid = pw->pw_gid;
        g_runas_gid_set = 1;
    }
}

static char **dup_user_env(char * const envp[]) {
    size_t count = 0;
    while (envp && envp[count]) {
        count++;
    }
    if (count == 0) {
        return NULL;
    }
    char **out = calloc(count + 1, sizeof(char *));
    if (!out) {
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        out[i] = strdup(envp[i]);
        if (!out[i]) {
            free_user_env(out);
            return NULL;
        }
    }
    out[count] = NULL;
    return out;
}

static char **build_fallback_env(void) {
    const char *path = getenv("PATH");
    if (!path) {
        return NULL;
    }
    size_t len = strlen(path);
    size_t total = sizeof("PATH=") - 1 + len + 1;
    char *entry = malloc(total);
    if (!entry) {
        return NULL;
    }
    snprintf(entry, total, "PATH=%s", path);
    char **out = calloc(2, sizeof(char *));
    if (!out) {
        free(entry);
        return NULL;
    }
    out[0] = entry;
    out[1] = NULL;
    return out;
}

static char *dup_kv(const char *key, const char *val) {
    size_t key_len = strlen(key);
    size_t val_len = val ? strlen(val) : 0;
    size_t total = key_len + 1 + val_len + 1;
    char *out = malloc(total);
    if (!out) {
        return NULL;
    }
    if (val) {
        snprintf(out, total, "%s=%s", key, val);
    } else {
        snprintf(out, total, "%s=", key);
    }
    return out;
}

static char **build_command_info(char * const argv[], const char *cmd, const char *cmd_path) {
    (void)argv;
    char cwd_buf[PATH_MAX];
    const char *cwd = getcwd(cwd_buf, sizeof(cwd_buf));
    if (!cwd) {
        cwd = "/";
    }

    char **info = calloc(7, sizeof(char *));
    if (!info) {
        return NULL;
    }
    info[0] = dup_kv("command", cmd);
    info[1] = dup_kv("command_path", cmd_path ? cmd_path : cmd);
    const char *runas_user = g_runas_user ? g_runas_user : SUDO_AWESOME_JWT_RUNAS_USER_DEFAULT;
    char uid_buf[32];
    char gid_buf[32];
    snprintf(uid_buf, sizeof(uid_buf), "%u",
             (unsigned)(g_runas_uid_set ? g_runas_uid : SUDO_AWESOME_JWT_RUNAS_UID_DEFAULT));
    snprintf(gid_buf, sizeof(gid_buf), "%u",
             (unsigned)(g_runas_gid_set ? g_runas_gid : SUDO_AWESOME_JWT_RUNAS_GID_DEFAULT));
    info[2] = dup_kv("runas_user", runas_user);
    info[3] = dup_kv("runas_uid", uid_buf);
    info[4] = dup_kv("runas_gid", gid_buf);
    info[5] = dup_kv("cwd", cwd);
    info[6] = NULL;

    for (size_t i = 0; i < 6; i++) {
        if (!info[i]) {
            free_command_info(info);
            return NULL;
        }
    }
    return info;
}

static const char *find_env_path(void) {
    if (g_user_env) {
        for (size_t i = 0; g_user_env[i]; i++) {
            const char *entry = g_user_env[i];
            if (strncmp(entry, "PATH=", 5) == 0 && entry[5] != '\0') {
                return entry + 5;
            }
        }
    }
    return getenv("PATH");
}

static char *resolve_command_path(const char *cmd) {
    if (!cmd || !*cmd) {
        return NULL;
    }
    if (strchr(cmd, '/')) {
        return strdup(cmd);
    }
    const char *path = find_env_path();
    if (!path) {
        return NULL;
    }
    const char *cur = path;
    while (*cur) {
        const char *end = strchr(cur, ':');
        size_t len = end ? (size_t)(end - cur) : strlen(cur);
        if (len > 0) {
            char candidate[PATH_MAX];
            if (snprintf(candidate, sizeof(candidate), "%.*s/%s", (int)len, cur, cmd) < (int)sizeof(candidate)) {
                if (access(candidate, X_OK) == 0) {
                    return strdup(candidate);
                }
            }
        }
        if (!end) {
            break;
        }
        cur = end + 1;
    }
    return NULL;
}

static char **dup_argv_with_cmd(char * const argv[], const char *cmd_path) {
    size_t count = 0;
    while (argv && argv[count]) {
        count++;
    }
    if (count == 0) {
        return NULL;
    }
    char **out = calloc(count + 1, sizeof(char *));
    if (!out) {
        return NULL;
    }
    out[0] = strdup(cmd_path);
    if (!out[0]) {
        free(out);
        return NULL;
    }
    for (size_t i = 1; i < count; i++) {
        out[i] = strdup(argv[i]);
        if (!out[i]) {
            free_argv_out(out);
            return NULL;
        }
    }
    out[count] = NULL;
    return out;
}

static int policy_open(unsigned int version, sudo_conv_t conversation,
                       sudo_printf_t sudo_plugin_printf, char * const settings[],
                       char * const user_info[], char * const user_env[],
                       char * const plugin_options[], const char **errstr) {
    (void)conversation;
    (void)settings;

    jwt_common_parse_debug_options(plugin_options);
    parse_runas_settings(settings);
    fill_runas_from_user();
    policy_debug("policy_open");
    int rc = jwt_common_open(version, sudo_plugin_printf, user_info, plugin_options, errstr);
    g_user_env = NULL;
    g_user_env_alloc = NULL;
    if (user_env) {
        g_user_env_alloc = dup_user_env(user_env);
        g_user_env = g_user_env_alloc ? g_user_env_alloc : (char **)user_env;
    } else {
        g_user_env_alloc = build_fallback_env();
        g_user_env = g_user_env_alloc;
    }
    if (rc != 1 && errstr && *errstr) {
        jwt_common_debug("%s:%s\n", SUDO_AWESOME_JWT_POLICY, *errstr);
    }
    return rc;
}

static void policy_close(int exit_status, int error) {
    (void)exit_status;
    (void)error;
    policy_debug("policy_close");
    free_command_info(g_command_info);
    g_command_info = NULL;
    if (g_user_env_alloc) {
        free_user_env(g_user_env_alloc);
    }
    g_user_env_alloc = NULL;
    g_user_env = NULL;
    if (g_argv_out_alloc) {
        free_argv_out(g_argv_out_alloc);
    }
    g_argv_out_alloc = NULL;
    reset_runas();
    g_env_empty[0] = NULL;
    jwt_common_close();
}

static int policy_show_version(int verbose) {
    return jwt_common_show_version(verbose, "Policy");
}

static int policy_check(int argc, char * const argv[], char *env_add[],
                        char **command_info[], char **argv_out[],
                        char **user_env_out[], const char **errstr) {
    (void)argc;
    (void)env_add;

    policy_debug("policy_check");
    char *resolved = resolve_command_path((argv && argv[0]) ? argv[0] : NULL);
    const char *cmd_path = resolved ? resolved : (argv && argv[0]) ? argv[0] : "";
    const char *cmd_for_info = resolved ? cmd_path : (argv && argv[0]) ? argv[0] : "";
    if (resolved) {
        jwt_common_debug("%s:resolved command_path=%s\n", SUDO_AWESOME_JWT_POLICY, resolved);
    }
    if (command_info) {
        free_command_info(g_command_info);
        g_command_info = build_command_info(argv, cmd_for_info, cmd_path);
        *command_info = g_command_info;
    }
    if (argv_out) {
        if (g_argv_out_alloc) {
            free_argv_out(g_argv_out_alloc);
            g_argv_out_alloc = NULL;
        }
        if (resolved && argv && argv[0] && strcmp(resolved, argv[0]) != 0) {
            g_argv_out_alloc = dup_argv_with_cmd(argv, resolved);
            if (g_argv_out_alloc) {
                *argv_out = g_argv_out_alloc;
            } else {
                *argv_out = (char **)argv;
            }
        } else {
            *argv_out = (char **)argv;
        }
        policy_debug_argv(*argv_out);
    }
    free(resolved);
    if (user_env_out) {
        if (g_user_env) {
            *user_env_out = g_user_env;
        } else {
            g_env_empty[0] = NULL;
            *user_env_out = g_env_empty;
        }
    }

    int rc = jwt_common_check(g_command_info, argv, errstr, SUDO_AWESOME_JWT_POLICY);
    jwt_common_debug("%s:policy_check rc=%d\n", SUDO_AWESOME_JWT_POLICY, rc);
    if (rc != 1 && errstr && *errstr) {
        jwt_common_debug("%s:%s\n", SUDO_AWESOME_JWT_POLICY, *errstr);
    }
    return rc;
}

static int policy_list(int argc, char * const argv[], int verbose, const char *user, const char **errstr) {
    (void)argc;
    (void)argv;
    (void)user;
    (void)errstr;

    policy_debug("policy_list");
    return jwt_common_show_version(verbose, "Policy");
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
