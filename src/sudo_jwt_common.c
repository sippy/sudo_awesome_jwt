#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "jsmn.h"
#include "sudo_jwt_common.h"

#define DEFAULT_CONFIG_PATH "/usr/local/etc/sudo_awesome_jwt.conf"
#define DEFAULT_SCOPE "sudo"
#define MAX_TOKEN_BYTES 16384
#define CLOCK_SKEW_SECONDS 60
#define MAX_AUDIENCE_BYTES 1024

struct policy_config {
    char *token_file;
    char *public_key;
    char *issuer;
    char *audience;
    char *scope;
    char *host;
    char **command_allowlist;
    size_t command_allowlist_len;
    long max_ttl;
    char *only_user;
    uid_t only_uid;
    int only_uid_set;
    int require_jwt;
    int require_tty;
};

static struct policy_config *g_cfg;
static sudo_printf_t g_printf;
static char *g_tty;
static char *g_user;
static uid_t g_uid;
static int g_uid_valid;

static int read_text_file(const char *path, size_t max_len, char **out, const char **errstr);

static void plugin_log(int msg_type, const char *fmt, ...) {
    if (!g_printf) {
        return;
    }

    va_list ap;
    char buf[1024];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    g_printf(msg_type, "%s", buf);
}

static void *xmalloc(size_t size) {
    void *p = malloc(size);
    if (!p) {
        abort();
    }
    return p;
}

static char *xstrdup(const char *s) {
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s) + 1;
    char *copy = xmalloc(len);
    memcpy(copy, s, len);
    return copy;
}

static char *trim_whitespace(char *s) {
    char *end;

    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        end--;
    }
    end[1] = '\0';
    return s;
}

static char *strip_quotes(char *s) {
    size_t len;

    if (!s) {
        return s;
    }
    len = strlen(s);
    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') || (s[0] == '\'' && s[len - 1] == '\''))) {
        s[len - 1] = '\0';
        return s + 1;
    }
    return s;
}

static int parse_bool(const char *s, int *out) {
    if (!s || !out) {
        return -1;
    }
    if (strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0 || strcasecmp(s, "yes") == 0) {
        *out = 1;
        return 0;
    }
    if (strcasecmp(s, "false") == 0 || strcmp(s, "0") == 0 || strcasecmp(s, "no") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static void free_config(struct policy_config *cfg) {
    if (!cfg) {
        return;
    }
    free(cfg->token_file);
    free(cfg->public_key);
    free(cfg->issuer);
    free(cfg->audience);
    free(cfg->scope);
    free(cfg->host);
    if (cfg->command_allowlist) {
        for (size_t i = 0; i < cfg->command_allowlist_len; i++) {
            free(cfg->command_allowlist[i]);
        }
        free(cfg->command_allowlist);
    }
    free(cfg->only_user);
    free(cfg);
}

static int load_config(const char *path, struct policy_config **out, const char **errstr) {
    FILE *fp;
    char line[1024];
    struct policy_config *cfg;

    fp = fopen(path, "r");
    if (!fp) {
        if (errstr) {
            *errstr = "unable to open policy config";
        }
        return -1;
    }

    cfg = calloc(1, sizeof(*cfg));
    if (!cfg) {
        fclose(fp);
        if (errstr) {
            *errstr = "out of memory";
        }
        return -1;
    }

    cfg->scope = xstrdup(DEFAULT_SCOPE);
    cfg->max_ttl = 300;
    cfg->require_jwt = 1;
    cfg->require_tty = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *eq;
        char *key;
        char *val;

        p = trim_whitespace(p);
        if (*p == '\0' || *p == '#') {
            continue;
        }

        eq = strchr(p, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        key = trim_whitespace(p);
        val = trim_whitespace(eq + 1);
        if (*val == '\0') {
            continue;
        }

        if (*val != '"' && *val != '\'') {
            char *hash = strchr(val, '#');
            if (hash) {
                *hash = '\0';
                val = trim_whitespace(val);
            }
        }

        int val_quoted = 0;
        size_t val_len = strlen(val);
        if (val_len >= 2 && ((val[0] == '"' && val[val_len - 1] == '"') || (val[0] == '\'' && val[val_len - 1] == '\''))) {
            val_quoted = 1;
        }

        val = strip_quotes(val);

        if (strcasecmp(key, "command_allowlist") == 0 || strcasecmp(key, "command_allowlist_csv") == 0) {
            char *cursor = val;
            while (cursor && *cursor) {
                char *comma = strchr(cursor, ',');
                char *entry;
                size_t entry_len;
                if (comma) {
                    *comma = '\0';
                }
                entry = trim_whitespace(cursor);
                entry_len = strlen(entry);
                if (entry_len > 0) {
                    char **next = realloc(cfg->command_allowlist, sizeof(char *) * (cfg->command_allowlist_len + 1));
                    if (!next) {
                        fclose(fp);
                        free_config(cfg);
                        if (errstr) {
                            *errstr = "out of memory";
                        }
                        return -1;
                    }
                    cfg->command_allowlist = next;
                    cfg->command_allowlist[cfg->command_allowlist_len++] = xstrdup(entry);
                }
                if (!comma) {
                    break;
                }
                cursor = comma + 1;
            }
            continue;
        }

        if (strcasecmp(key, "token_file") == 0) {
            free(cfg->token_file);
            cfg->token_file = xstrdup(val);
        } else if (strcasecmp(key, "public_key") == 0) {
            free(cfg->public_key);
            cfg->public_key = xstrdup(val);
        } else if (strcasecmp(key, "issuer") == 0) {
            free(cfg->issuer);
            cfg->issuer = xstrdup(val);
        } else if (strcasecmp(key, "audience") == 0) {
            free(cfg->audience);
            cfg->audience = NULL;
            if (!val_quoted && val[0] == '/') {
                if (read_text_file(val, MAX_AUDIENCE_BYTES, &cfg->audience, errstr) != 0) {
                    fclose(fp);
                    free_config(cfg);
                    return -1;
                }
            } else {
                cfg->audience = xstrdup(val);
            }
        } else if (strcasecmp(key, "scope") == 0) {
            free(cfg->scope);
            cfg->scope = xstrdup(val);
        } else if (strcasecmp(key, "host") == 0) {
            free(cfg->host);
            cfg->host = xstrdup(val);
        } else if (strcasecmp(key, "max_ttl") == 0) {
            cfg->max_ttl = strtol(val, NULL, 10);
        } else if (strcasecmp(key, "only_user") == 0) {
            free(cfg->only_user);
            cfg->only_user = xstrdup(val);
        } else if (strcasecmp(key, "only_uid") == 0) {
            char *endp = NULL;
            long long uid_val;
            errno = 0;
            uid_val = strtoll(val, &endp, 10);
            if (errno == 0 && endp != val && uid_val >= 0) {
                cfg->only_uid = (uid_t)uid_val;
                cfg->only_uid_set = 1;
            }
        } else if (strcasecmp(key, "require_tty") == 0) {
            int bval;
            if (parse_bool(val, &bval) == 0) {
                cfg->require_tty = bval;
            }
        } else if (strcasecmp(key, "require_jwt") == 0) {
            int bval;
            if (parse_bool(val, &bval) == 0) {
                cfg->require_jwt = bval;
            }
        }
    }

    fclose(fp);

    if (!cfg->token_file || !cfg->public_key || !cfg->issuer || !cfg->audience) {
        free_config(cfg);
        if (errstr) {
            *errstr = "missing required config key";
        }
        return -1;
    }

    if (!cfg->scope) {
        cfg->scope = xstrdup(DEFAULT_SCOPE);
    }

    *out = cfg;
    return 0;
}

static const char *get_kv(char * const list[], const char *key) {
    size_t key_len;

    if (!list || !key) {
        return NULL;
    }
    key_len = strlen(key);
    for (size_t i = 0; list[i]; i++) {
        if (strncmp(list[i], key, key_len) == 0 && list[i][key_len] == '=') {
            return list[i] + key_len + 1;
        }
    }
    return NULL;
}

static int read_file(const char *path, char **out, size_t *out_len, int *out_errno, const char **errstr) {
    int fd;
    struct stat st;
    ssize_t nread;
    char *buf;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (out_errno) {
            *out_errno = errno;
        }
        if (errstr) {
            *errstr = "unable to open token file";
        }
        return -1;
    }

    if (fstat(fd, &st) != 0) {
        close(fd);
        if (out_errno) {
            *out_errno = errno;
        }
        if (errstr) {
            *errstr = "unable to stat token file";
        }
        return -1;
    }

    if ((st.st_mode & 022) != 0) {
        close(fd);
        if (out_errno) {
            *out_errno = EPERM;
        }
        if (errstr) {
            *errstr = "token file is writable by group or others";
        }
        return -1;
    }

    if (st.st_size <= 0 || st.st_size > MAX_TOKEN_BYTES) {
        close(fd);
        if (out_errno) {
            *out_errno = EINVAL;
        }
        if (errstr) {
            *errstr = "token file size invalid";
        }
        return -1;
    }

    buf = xmalloc((size_t)st.st_size + 1);
    nread = read(fd, buf, (size_t)st.st_size);
    close(fd);

    if (nread <= 0) {
        free(buf);
        if (out_errno) {
            *out_errno = EIO;
        }
        if (errstr) {
            *errstr = "unable to read token";
        }
        return -1;
    }

    buf[nread] = '\0';

    if (out) {
        *out = buf;
    }
    if (out_len) {
        *out_len = (size_t)nread;
    }
    return 0;
}

static int read_text_file(const char *path, size_t max_len, char **out, const char **errstr) {
    int fd;
    struct stat st;
    ssize_t nread;
    char *buf;
    char *trimmed;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errstr) {
            *errstr = "unable to open audience file";
        }
        return -1;
    }

    if (fstat(fd, &st) != 0) {
        close(fd);
        if (errstr) {
            *errstr = "unable to stat audience file";
        }
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        if (errstr) {
            *errstr = "audience file is not regular";
        }
        return -1;
    }

    if ((st.st_mode & 022) != 0) {
        close(fd);
        if (errstr) {
            *errstr = "audience file is writable by group or others";
        }
        return -1;
    }

    if (st.st_size <= 0 || st.st_size > (off_t)max_len) {
        close(fd);
        if (errstr) {
            *errstr = "audience file size invalid";
        }
        return -1;
    }

    buf = xmalloc((size_t)st.st_size + 1);
    nread = read(fd, buf, (size_t)st.st_size);
    close(fd);

    if (nread <= 0) {
        free(buf);
        if (errstr) {
            *errstr = "unable to read audience file";
        }
        return -1;
    }

    buf[nread] = '\0';
    trimmed = trim_whitespace(buf);
    if (trimmed[0] == '\0') {
        free(buf);
        if (errstr) {
            *errstr = "audience file empty";
        }
        return -1;
    }

    *out = xstrdup(trimmed);
    free(buf);
    return 0;
}

static int should_enforce_for_user(void) {
    if (!g_cfg) {
        return 0;
    }

    if (g_cfg->only_user && g_user && strcmp(g_cfg->only_user, g_user) != 0) {
        return 0;
    }

    if (g_cfg->only_uid_set && (!g_uid_valid || g_uid != g_cfg->only_uid)) {
        return 0;
    }

    return 1;
}

static const char *get_command_path(char * const run_argv[], char * const command_info[]) {
    if (command_info) {
        const char *cmd = get_kv(command_info, "command");
        if (cmd && *cmd) {
            return cmd;
        }
        cmd = get_kv(command_info, "command_path");
        if (cmd && *cmd) {
            return cmd;
        }
    }

    if (run_argv && run_argv[0] && run_argv[0][0] != '\0') {
        return run_argv[0];
    }

    return NULL;
}

static int command_requires_jwt(char * const run_argv[], char * const command_info[]) {
    if (!g_cfg || g_cfg->command_allowlist_len == 0) {
        return 1;
    }

    const char *cmd = get_command_path(run_argv, command_info);
    if (!cmd) {
        return 1;
    }

    for (size_t i = 0; i < g_cfg->command_allowlist_len; i++) {
        if (strcmp(cmd, g_cfg->command_allowlist[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

static int base64url_decode(const char *in, unsigned char **out, size_t *out_len, const char **errstr) {
    size_t len;
    size_t pad;
    size_t b64_len;
    size_t max_len;
    char *tmp;
    unsigned char *buf;
    int decoded;

    if (!in) {
        if (errstr) {
            *errstr = "invalid base64 input";
        }
        return -1;
    }

    len = strlen(in);
    pad = (4 - (len % 4)) % 4;
    b64_len = len + pad;

    tmp = xmalloc(b64_len + 1);
    for (size_t i = 0; i < len; i++) {
        char c = in[i];
        if (c == '-') {
            c = '+';
        } else if (c == '_') {
            c = '/';
        }
        tmp[i] = c;
    }
    for (size_t i = 0; i < pad; i++) {
        tmp[len + i] = '=';
    }
    tmp[b64_len] = '\0';

    max_len = (b64_len / 4) * 3;
    buf = xmalloc(max_len + 1);
    decoded = EVP_DecodeBlock(buf, (unsigned char *)tmp, (int)b64_len);
    free(tmp);

    if (decoded < 0) {
        free(buf);
        if (errstr) {
            *errstr = "base64 decode failed";
        }
        return -1;
    }

    if (pad > 0 && (size_t)decoded >= pad) {
        decoded -= (int)pad;
    }

    buf[decoded] = '\0';
    *out = buf;
    if (out_len) {
        *out_len = (size_t)decoded;
    }
    return 0;
}

static int token_eq(const char *json, const jsmntok_t *tok, const char *s) {
    size_t len;
    if (!json || !tok || !s || tok->type != JSMN_STRING) {
        return 0;
    }
    len = (size_t)(tok->end - tok->start);
    return strlen(s) == len && strncmp(json + tok->start, s, len) == 0;
}

static int token_copy_string(const char *json, const jsmntok_t *tok, char *buf, size_t buflen) {
    size_t len;

    if (!json || !tok || !buf || buflen == 0 || tok->type != JSMN_STRING) {
        return -1;
    }
    len = (size_t)(tok->end - tok->start);
    if (len + 1 > buflen) {
        return -1;
    }
    memcpy(buf, json + tok->start, len);
    buf[len] = '\0';
    return 0;
}

static int skip_token(jsmntok_t *tokens, int index) {
    int i;

    if (tokens[index].type == JSMN_OBJECT) {
        int count = tokens[index].size;
        i = index + 1;
        for (int p = 0; p < count; p++) {
            i = skip_token(tokens, i);
            i = skip_token(tokens, i);
        }
        return i;
    }
    if (tokens[index].type == JSMN_ARRAY) {
        int count = tokens[index].size;
        i = index + 1;
        for (int p = 0; p < count; p++) {
            i = skip_token(tokens, i);
        }
        return i;
    }
    return index + 1;
}

static int find_value_token(const char *json, jsmntok_t *tokens, int tok_count, const char *key) {
    if (!json || !tokens || tok_count <= 0 || !key) {
        return -1;
    }
    for (int i = 1; i < tok_count; i++) {
        if (tokens[i].type == JSMN_STRING && token_eq(json, &tokens[i], key)) {
            return i + 1;
        }
    }
    return -1;
}

static int parse_int64(const char *json, const jsmntok_t *tok, long long *out) {
    char buf[64];
    size_t len;
    char *endp;

    if (!json || !tok || !out || tok->type != JSMN_PRIMITIVE) {
        return -1;
    }
    len = (size_t)(tok->end - tok->start);
    if (len == 0 || len >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, json + tok->start, len);
    buf[len] = '\0';
    errno = 0;
    *out = strtoll(buf, &endp, 10);
    if (errno != 0 || endp == buf) {
        return -1;
    }
    return 0;
}

static int scope_string_has(const char *s, size_t len, const char *required) {
    size_t req_len = strlen(required);
    size_t i = 0;

    while (i < len) {
        size_t start;
        size_t tok_len;

        while (i < len && (isspace((unsigned char)s[i]) || s[i] == ',')) {
            i++;
        }
        if (i >= len) {
            break;
        }
        start = i;
        while (i < len && !isspace((unsigned char)s[i]) && s[i] != ',') {
            i++;
        }
        tok_len = i - start;
        if (tok_len == req_len && strncmp(s + start, required, req_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static int scope_has_required(const char *json, jsmntok_t *tokens, int idx, const char *required) {
    if (idx < 0 || !required) {
        return 0;
    }
    if (tokens[idx].type == JSMN_STRING) {
        size_t len = (size_t)(tokens[idx].end - tokens[idx].start);
        return scope_string_has(json + tokens[idx].start, len, required);
    }
    if (tokens[idx].type == JSMN_ARRAY) {
        int count = tokens[idx].size;
        int i = idx + 1;
        for (int p = 0; p < count; p++) {
            if (tokens[i].type == JSMN_STRING && token_eq(json, &tokens[i], required)) {
                return 1;
            }
            i = skip_token(tokens, i);
        }
    }
    return 0;
}

static int aud_matches(const char *json, jsmntok_t *tokens, int idx, const char *expected) {
    if (idx < 0 || !expected) {
        return 0;
    }
    if (tokens[idx].type == JSMN_STRING) {
        return token_eq(json, &tokens[idx], expected);
    }
    if (tokens[idx].type == JSMN_ARRAY) {
        int count = tokens[idx].size;
        int i = idx + 1;
        for (int p = 0; p < count; p++) {
            if (tokens[i].type == JSMN_STRING && token_eq(json, &tokens[i], expected)) {
                return 1;
            }
            i = skip_token(tokens, i);
        }
    }
    return 0;
}

static EVP_PKEY *load_public_key(const char *path, const char **errstr) {
    EVP_PKEY *pkey = NULL;
    FILE *fp = fopen(path, "r");

    if (!fp) {
        if (errstr) {
            *errstr = "unable to open public key";
        }
        return NULL;
    }

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey && errstr) {
        *errstr = "unable to read public key";
    }
    return pkey;
}

static int verify_signature_rs256(EVP_PKEY *pkey, const unsigned char *data, size_t data_len,
                                 const unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;

    if (!ctx) {
        return 0;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    ok = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    EVP_MD_CTX_free(ctx);
    return ok == 1;
}

static int verify_signature_eddsa(EVP_PKEY *pkey, const unsigned char *data, size_t data_len,
                                  const unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok;

    if (!ctx) {
        return 0;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    ok = EVP_DigestVerify(ctx, sig, sig_len, data, data_len);
    EVP_MD_CTX_free(ctx);
    return ok == 1;
}

struct jwt_payload {
    char *json;
    jsmntok_t *tokens;
    int tok_count;
};

static void free_payload(struct jwt_payload *payload) {
    if (!payload) {
        return;
    }
    free(payload->json);
    free(payload->tokens);
    free(payload);
}

static struct jwt_payload *verify_jwt(const char *token, const char *pubkey_path, const char **errstr) {
    char *token_copy;
    char *header_b64;
    char *payload_b64;
    char *sig_b64;
    char *dot1;
    char *dot2;
    unsigned char *header_json = NULL;
    unsigned char *payload_json = NULL;
    unsigned char *sig = NULL;
    size_t header_len = 0;
    size_t payload_len = 0;
    size_t sig_len = 0;
    char alg[32];
    EVP_PKEY *pkey = NULL;
    struct jwt_payload *payload = NULL;
    int verified = 0;

    token_copy = xstrdup(token);
    dot1 = strchr(token_copy, '.');
    if (!dot1) {
        if (errstr) {
            *errstr = "token missing header";
        }
        goto cleanup;
    }
    *dot1 = '\0';
    header_b64 = token_copy;

    dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        if (errstr) {
            *errstr = "token missing signature";
        }
        goto cleanup;
    }
    *dot2 = '\0';
    payload_b64 = dot1 + 1;
    sig_b64 = dot2 + 1;

    if (base64url_decode(header_b64, &header_json, &header_len, errstr) != 0) {
        goto cleanup;
    }
    if (base64url_decode(payload_b64, &payload_json, &payload_len, errstr) != 0) {
        goto cleanup;
    }
    if (base64url_decode(sig_b64, &sig, &sig_len, errstr) != 0) {
        goto cleanup;
    }

    jsmn_parser parser;
    jsmntok_t header_tokens[64];
    int header_count;

    jsmn_init(&parser);
    header_count = jsmn_parse(&parser, (char *)header_json, header_len, header_tokens, 64);
    if (header_count < 0) {
        if (errstr) {
            *errstr = "invalid header JSON";
        }
        goto cleanup;
    }

    int alg_idx = find_value_token((char *)header_json, header_tokens, header_count, "alg");
    if (alg_idx < 0 || token_copy_string((char *)header_json, &header_tokens[alg_idx], alg, sizeof(alg)) != 0) {
        if (errstr) {
            *errstr = "missing alg";
        }
        goto cleanup;
    }

    pkey = load_public_key(pubkey_path, errstr);
    if (!pkey) {
        goto cleanup;
    }

    size_t signing_len = strlen(header_b64) + 1 + strlen(payload_b64);
    char *signing_input = xmalloc(signing_len + 1);
    snprintf(signing_input, signing_len + 1, "%s.%s", header_b64, payload_b64);

    if (strcmp(alg, "RS256") == 0) {
        verified = verify_signature_rs256(pkey, (unsigned char *)signing_input, signing_len, sig, sig_len);
    } else if (strcmp(alg, "EdDSA") == 0) {
        verified = verify_signature_eddsa(pkey, (unsigned char *)signing_input, signing_len, sig, sig_len);
    } else {
        if (errstr) {
            *errstr = "unsupported alg";
        }
    }

    free(signing_input);

    if (!verified) {
        if (errstr) {
            *errstr = "signature verification failed";
        }
        goto cleanup;
    }

    payload = calloc(1, sizeof(*payload));
    if (!payload) {
        if (errstr) {
            *errstr = "out of memory";
        }
        goto cleanup;
    }

    payload->json = (char *)payload_json;
    payload_json = NULL;

    payload->tokens = calloc(256, sizeof(jsmntok_t));
    if (!payload->tokens) {
        if (errstr) {
            *errstr = "out of memory";
        }
        goto cleanup;
    }

    jsmn_init(&parser);
    payload->tok_count = jsmn_parse(&parser, payload->json, strlen(payload->json), payload->tokens, 256);
    if (payload->tok_count < 0) {
        if (errstr) {
            *errstr = "invalid payload JSON";
        }
        goto cleanup;
    }

cleanup:
    if (!payload) {
        free(payload_json);
    }
    free(header_json);
    free(sig);
    free(token_copy);
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return payload;
}

static int check_claims(struct jwt_payload *payload, const char **errstr) {
    long long exp = 0;
    long long iat = 0;
    int exp_idx;
    int iat_idx;
    int iss_idx;
    int aud_idx;
    int scope_idx;
    int host_idx;
    time_t now = time(NULL);

    if (!payload || !payload->json || !payload->tokens) {
        if (errstr) {
            *errstr = "invalid payload";
        }
        return 0;
    }

    iss_idx = find_value_token(payload->json, payload->tokens, payload->tok_count, "iss");
    if (iss_idx < 0 || !token_eq(payload->json, &payload->tokens[iss_idx], g_cfg->issuer)) {
        if (errstr) {
            *errstr = "issuer mismatch";
        }
        return 0;
    }

    aud_idx = find_value_token(payload->json, payload->tokens, payload->tok_count, "aud");
    if (aud_idx < 0 || !aud_matches(payload->json, payload->tokens, aud_idx, g_cfg->audience)) {
        if (errstr) {
            *errstr = "audience mismatch";
        }
        return 0;
    }

    exp_idx = find_value_token(payload->json, payload->tokens, payload->tok_count, "exp");
    if (exp_idx < 0 || parse_int64(payload->json, &payload->tokens[exp_idx], &exp) != 0) {
        if (errstr) {
            *errstr = "missing exp";
        }
        return 0;
    }

    iat_idx = find_value_token(payload->json, payload->tokens, payload->tok_count, "iat");
    if (iat_idx < 0 || parse_int64(payload->json, &payload->tokens[iat_idx], &iat) != 0) {
        if (errstr) {
            *errstr = "missing iat";
        }
        return 0;
    }

    if (now > (time_t)(exp + CLOCK_SKEW_SECONDS)) {
        if (errstr) {
            *errstr = "token expired";
        }
        return 0;
    }

    if (now + CLOCK_SKEW_SECONDS < (time_t)iat) {
        if (errstr) {
            *errstr = "token issued in future";
        }
        return 0;
    }

    if (g_cfg->max_ttl > 0) {
        if (exp - iat > g_cfg->max_ttl) {
            if (errstr) {
                *errstr = "token ttl too long";
            }
            return 0;
        }
        if (now - iat > g_cfg->max_ttl + CLOCK_SKEW_SECONDS) {
            if (errstr) {
                *errstr = "token too old";
            }
            return 0;
        }
    }

    scope_idx = find_value_token(payload->json, payload->tokens, payload->tok_count, "scope");
    if (scope_idx < 0 || !scope_has_required(payload->json, payload->tokens, scope_idx, g_cfg->scope)) {
        if (errstr) {
            *errstr = "missing scope";
        }
        return 0;
    }

    if (g_cfg->host) {
        host_idx = find_value_token(payload->json, payload->tokens, payload->tok_count, "host");
        if (host_idx < 0 || !token_eq(payload->json, &payload->tokens[host_idx], g_cfg->host)) {
            if (errstr) {
                *errstr = "host mismatch";
            }
            return 0;
        }
    }

    return 1;
}

int jwt_common_open(unsigned int version, sudo_printf_t sudo_plugin_printf,
                    char * const user_info[], char * const plugin_options[],
                    const char **errstr) {
    const char *config_path = DEFAULT_CONFIG_PATH;

    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
        if (errstr) {
            *errstr = "incompatible sudo plugin API";
        }
        return -1;
    }

    g_printf = sudo_plugin_printf;

    if (plugin_options) {
        for (size_t i = 0; plugin_options[i]; i++) {
            const char *opt = plugin_options[i];
            if (strncmp(opt, "config=", 7) == 0) {
                config_path = opt + 7;
            }
        }
    }

    free(g_tty);
    g_tty = NULL;
    free(g_user);
    g_user = NULL;
    g_uid_valid = 0;
    if (user_info) {
        const char *tty = get_kv(user_info, "tty");
        if (tty && *tty) {
            g_tty = xstrdup(tty);
        }

        const char *user = get_kv(user_info, "user");
        if (user && *user) {
            g_user = xstrdup(user);
        }

        const char *uid = get_kv(user_info, "uid");
        if (uid && *uid) {
            char *endp = NULL;
            long long uid_val;
            errno = 0;
            uid_val = strtoll(uid, &endp, 10);
            if (errno == 0 && endp != uid && uid_val >= 0) {
                g_uid = (uid_t)uid_val;
                g_uid_valid = 1;
            }
        }
    }

    free_config(g_cfg);
    g_cfg = NULL;
    if (load_config(config_path, &g_cfg, errstr) != 0) {
        return -1;
    }

    return 1;
}

void jwt_common_close(void) {
    free_config(g_cfg);
    g_cfg = NULL;
    free(g_tty);
    g_tty = NULL;
    free(g_user);
    g_user = NULL;
    g_uid_valid = 0;
    g_printf = NULL;
}

int jwt_common_check(char * const command_info[], char * const run_argv[],
                     const char **errstr, const char *log_prefix) {
    char *token = NULL;
    char *token_buf = NULL;
    struct jwt_payload *payload = NULL;
    int token_errno = 0;
    int ok = 0;

    if (!g_cfg) {
        if (errstr) {
            *errstr = "policy not initialized";
        }
        return -1;
    }

    if (!should_enforce_for_user()) {
        return 1;
    }

    if (!command_requires_jwt(run_argv, command_info)) {
        return 1;
    }

    if (g_cfg->require_tty && (!g_tty || g_tty[0] == '\0')) {
        if (errstr) {
            *errstr = "tty required";
        }
        return 0;
    }

    if (read_file(g_cfg->token_file, &token, NULL, &token_errno, errstr) != 0) {
        if (!g_cfg->require_jwt && token_errno == ENOENT) {
            return 1;
        }
        goto cleanup;
    }

    token_buf = token;
    token = trim_whitespace(token_buf);
    if (token[0] == '\0') {
        if (errstr) {
            *errstr = "empty token";
        }
        goto cleanup;
    }

    payload = verify_jwt(token, g_cfg->public_key, errstr);
    if (!payload) {
        goto cleanup;
    }

    if (!check_claims(payload, errstr)) {
        goto cleanup;
    }

    ok = 1;

cleanup:
    if (!ok && errstr && *errstr) {
        const char *prefix = (log_prefix && log_prefix[0] != '\0') ? log_prefix : "sudo-jwt";
        plugin_log(SUDO_CONV_ERROR_MSG, "%s: %s\n", prefix, *errstr);
    }
    free_payload(payload);
    free(token_buf);
    return ok ? 1 : 0;
}

int jwt_common_show_version(int verbose, const char *label) {
    if (verbose && g_printf) {
        const char *name = (label && label[0] != '\0') ? label : "sudo-jwt";
        g_printf(SUDO_CONV_INFO_MSG, "%s 0.1\n", name);
    }
    return 1;
}
