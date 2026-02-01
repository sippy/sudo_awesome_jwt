#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORKDIR=$(mktemp -d /tmp/sudo-awesome-jwt-test.XXXXXX)
SUDO_CONF=/etc/sudo.conf
SUDO_CONF_BACKUP="$WORKDIR/sudo.conf.bak"
CONFIG_FILE="$WORKDIR/sudo_awesome_jwt.conf"
TOKEN_FILE="$WORKDIR/token.jwt"
KEY_PRIV="$WORKDIR/jwt.key"
KEY_PUB="$WORKDIR/jwt.pub"
SUDO_DEBUG_LOG="$WORKDIR/sudo_debug.log"
PLUGIN_DEBUG_LOG="$WORKDIR/sudo_plugin_debug.log"

PLUGIN_LIB=${SUDO_AWESOME_JWT_PLUGIN_LIB:-"$ROOT_DIR/sudo_awesome_jwt.so"}
PLUGIN_BASENAME=$(basename "$PLUGIN_LIB")
TEST_COMMANDS=()
WAIT_SECS=${SUDO_AWESOME_JWT_TEST_WAIT:-70}
TTL_SECS=${SUDO_AWESOME_JWT_TEST_TTL:-5}
INTERACTIVE=${SUDO_AWESOME_JWT_TEST_INTERACTIVE:-0}
DEBUG=${SUDO_AWESOME_JWT_DEBUG:-0}
DEBUG_OPT=""
RUNAS_USER=${SUDO_AWESOME_JWT_TEST_RUNAS_USER:-nobody}
RUNAS_UID=""
RUNAS_GID=""
RUNAS_GROUP=${SUDO_AWESOME_JWT_TEST_RUNAS_GROUP:-root}
RUNAS_GROUP_GID=""
DENY_CMD=${SUDO_AWESOME_JWT_TEST_DENY_COMMAND:-true}
MISMATCH_RUNAS_USER=${SUDO_AWESOME_JWT_TEST_MISMATCH_USER:-}
MISMATCH_RUNAS_GROUP=${SUDO_AWESOME_JWT_TEST_MISMATCH_GROUP:-}
MISMATCH_RUNAS_GROUP_GID=""
ID_CMD=$(command -v id || echo "/usr/bin/id")
PRINTENV_CMD=$(command -v printenv || echo "/usr/bin/printenv")
SETENV_TEST_VAR=${SUDO_AWESOME_JWT_TEST_ENVVAR:-SUDO_AWESOME_JWT_TEST_SENTINEL}
SETENV_TEST_VALUE=${SUDO_AWESOME_JWT_TEST_ENVVAL:-"jwt-test-$RANDOM"}
JWT_SUB=${SUDO_AWESOME_JWT_TEST_SUB:-$("$ID_CMD" -un 2>/dev/null || true)}
if [[ -z "$JWT_SUB" ]]; then
    JWT_SUB="root"
fi

if [[ -n "${SUDO_AWESOME_JWT_TEST_COMMANDS:-}" ]]; then
    IFS=',' read -r -a TEST_COMMANDS <<< "${SUDO_AWESOME_JWT_TEST_COMMANDS}"
elif [[ -n "${SUDO_AWESOME_JWT_TEST_COMMAND:-}" ]]; then
    TEST_COMMANDS=("${SUDO_AWESOME_JWT_TEST_COMMAND}")
else
    TEST_COMMANDS=("/bin/id" "id")
fi

if [[ "${#TEST_COMMANDS[@]}" -gt 0 ]]; then
    SANITIZED_COMMANDS=()
    for cmd in "${TEST_COMMANDS[@]}"; do
        cmd="${cmd#"${cmd%%[![:space:]]*}"}"
        cmd="${cmd%"${cmd##*[![:space:]]}"}"
        if [[ -n "$cmd" ]]; then
            SANITIZED_COMMANDS+=("$cmd")
        fi
    done
    TEST_COMMANDS=("${SANITIZED_COMMANDS[@]}")
fi

if [[ "${#TEST_COMMANDS[@]}" -eq 0 ]]; then
    TEST_COMMANDS=("/bin/id" "id")
fi

if [[ -n "$RUNAS_USER" ]]; then
    if "$ID_CMD" -u "$RUNAS_USER" >/dev/null 2>&1; then
        RUNAS_UID=$("$ID_CMD" -u "$RUNAS_USER" 2>/dev/null || true)
        RUNAS_GID=$("$ID_CMD" -g "$RUNAS_USER" 2>/dev/null || true)
    else
        RUNAS_USER=""
    fi
fi

resolve_group_gid() {
    local group="$1"
    local gid=""
    if [[ -z "$group" ]]; then
        return 1
    fi
    if command -v getent >/dev/null 2>&1; then
        gid=$(getent group "$group" 2>/dev/null | awk -F: '{print $3}')
    fi
    if [[ -z "$gid" && -f /etc/group ]]; then
        gid=$(awk -F: -v name="$group" '$1 == name {print $3; exit}' /etc/group)
    fi
    if [[ -n "$gid" ]]; then
        printf '%s' "$gid"
        return 0
    fi
    return 1
}

if [[ -n "$RUNAS_GROUP" ]]; then
    RUNAS_GROUP_GID=$(resolve_group_gid "$RUNAS_GROUP" || true)
    if [[ -z "$RUNAS_GROUP_GID" ]]; then
        RUNAS_GROUP=""
    fi
fi

find_non_root_user() {
    local user=""
    if command -v getent >/dev/null 2>&1; then
        user=$(getent passwd 2>/dev/null | awk -F: '$3 != 0 {print $1; exit}')
    fi
    if [[ -z "$user" && -f /etc/passwd ]]; then
        user=$(awk -F: '$3 != 0 {print $1; exit}' /etc/passwd)
    fi
    if [[ -n "$user" ]]; then
        printf '%s' "$user"
        return 0
    fi
    return 1
}

if [[ -z "$MISMATCH_RUNAS_USER" ]]; then
    MISMATCH_RUNAS_USER=$(find_non_root_user || true)
fi

if [[ -n "$MISMATCH_RUNAS_USER" ]]; then
    if [[ "$MISMATCH_RUNAS_USER" == "root" ]] || ! "$ID_CMD" -u "$MISMATCH_RUNAS_USER" >/dev/null 2>&1; then
        MISMATCH_RUNAS_USER=""
    fi
fi

if [[ -z "$MISMATCH_RUNAS_GROUP" ]]; then
    if [[ "$RUNAS_GROUP" == "root" ]]; then
        for candidate in wheel nogroup nobody; do
            if resolve_group_gid "$candidate" >/dev/null 2>&1; then
                MISMATCH_RUNAS_GROUP="$candidate"
                break
            fi
        done
    else
        MISMATCH_RUNAS_GROUP="root"
    fi
fi

if [[ -n "$MISMATCH_RUNAS_GROUP" ]]; then
    MISMATCH_RUNAS_GROUP_GID=$(resolve_group_gid "$MISMATCH_RUNAS_GROUP" || true)
    if [[ -z "$MISMATCH_RUNAS_GROUP_GID" || "$MISMATCH_RUNAS_GROUP" == "$RUNAS_GROUP" ]]; then
        MISMATCH_RUNAS_GROUP=""
        MISMATCH_RUNAS_GROUP_GID=""
    fi
fi

ALLOW_SETENV_USER=${SUDO_AWESOME_JWT_TEST_SETENV_USER:-$("$ID_CMD" -un 2>/dev/null || true)}
ALLOW_SETENV_UID=""
ALLOW_SETENV_GID=""
if [[ -n "$ALLOW_SETENV_USER" ]]; then
    if "$ID_CMD" -u "$ALLOW_SETENV_USER" >/dev/null 2>&1; then
        ALLOW_SETENV_UID=$("$ID_CMD" -u "$ALLOW_SETENV_USER" 2>/dev/null || true)
        ALLOW_SETENV_GID=$("$ID_CMD" -g "$ALLOW_SETENV_USER" 2>/dev/null || true)
    else
        ALLOW_SETENV_USER=""
    fi
fi

ROOT_UID=0
ROOT_GID=0
if "$ID_CMD" -u root >/dev/null 2>&1; then
    ROOT_UID=$("$ID_CMD" -u root 2>/dev/null || echo 0)
    ROOT_GID=$("$ID_CMD" -g root 2>/dev/null || echo 0)
fi

JWT_CMDS=""
JWT_RUNAS_USERS=""
JWT_SETENV_RUNAS=""

resolve_realpath() {
    local path="$1"
    if command -v readlink >/dev/null 2>&1; then
        readlink -f "$path" 2>/dev/null || true
    elif command -v realpath >/dev/null 2>&1; then
        realpath "$path" 2>/dev/null || true
    else
        echo ""
    fi
}

resolve_cmd_for_jwt() {
    local cmd="$1"
    local resolved=""

    if [[ -z "$cmd" ]]; then
        return 1
    fi

    if [[ "$cmd" == /* ]]; then
        resolved="$cmd"
    else
        resolved=$(command -v -- "$cmd" 2>/dev/null || true)
    fi

    if [[ -z "$resolved" ]]; then
        return 1
    fi

    local canon
    canon=$(resolve_realpath "$resolved")
    if [[ -n "$canon" ]]; then
        resolved="$canon"
    fi

    if [[ "$resolved" != /* ]]; then
        return 1
    fi

    printf '%s' "$resolved"
}

DENY_CMD_RESOLVED=""
if [[ -n "$DENY_CMD" ]]; then
    DENY_CMD_RESOLVED=$(resolve_cmd_for_jwt "$DENY_CMD" || true)
    if [[ -z "$DENY_CMD_RESOLVED" ]]; then
        DENY_CMD=""
    fi
fi

prepare_jwt_env() {
    local cmd="$1"
    local runas_user="$2"
    local runas_uid="$3"
    local runas_gid="$4"
    local setenv="$5"
    local include_ids="$6"
    local fake_count="$7"
    local include_runas_entries="${8:-1}"
    local runas_group="${9:-}"

    local resolved
    resolved=$(resolve_cmd_for_jwt "$cmd") || {
        echo "unable to resolve command for JWT: $cmd" >&2
        return 1
    }

    JWT_CMDS="$resolved"$'\n'
    JWT_RUNAS_USERS=""
    JWT_SETENV_RUNAS=""
    JWT_INCLUDE_RUNAS_IDS="${include_ids:-1}"
    JWT_INCLUDE_RUNAS_ENTRIES="${include_runas_entries:-1}"
    JWT_FAKE_COUNT="${fake_count:-0}"
    JWT_FAKE_USER="${runas_user:-root}"
    JWT_FAKE_UID="${runas_uid:-0}"
    JWT_FAKE_GID="${runas_gid:-0}"
    JWT_RUNAS_GROUP="${runas_group}"

    if [[ -n "$runas_user" && "$JWT_INCLUDE_RUNAS_ENTRIES" != "0" ]]; then
        JWT_RUNAS_USERS+="$runas_user:$runas_uid:$runas_gid"$'\n'
    fi
    if [[ "$setenv" == "1" && -n "$runas_user" ]]; then
        JWT_SETENV_RUNAS+="$runas_user:$runas_uid:$runas_gid"$'\n'
    fi
}

log() {
    echo "[test] $*"
}

log_err() {
    echo "[test] $*" >&2
}

debug() {
    if [[ "$DEBUG" == "1" ]]; then
        echo "[debug] $*" >&2
    fi
}

dump_debug() {
    if [[ "$DEBUG" != "1" ]]; then
        return
    fi
    FILTER="${1:-"tail -n 200"}"
    {
        echo "[debug] sudo.conf plugin lines:"
        run_privileged awk '/^Plugin/ {print NR ":" $0}' "$SUDO_CONF" || true
        if command -v nm >/dev/null; then
            echo "[debug] exported symbols (filtered):"
            nm -D "$PLUGIN_LIB" 2>/dev/null | awk '/(approval|policy)/ {print}' || true
        elif command -v objdump >/dev/null; then
            echo "[debug] exported symbols (filtered):"
            objdump -T "$PLUGIN_LIB" 2>/dev/null | awk '/(approval|policy)/ {print}' || true
        fi
        if [[ -f "$SUDO_DEBUG_LOG" ]]; then
            echo "[debug] sudo debug log path: $SUDO_DEBUG_LOG"
            echo "[debug] sudo debug log (plugin/load):"
            grep -E "sudo_load_plugin|sudo_load_plugins|dlopen|dlsym|plugin|policy" "$SUDO_DEBUG_LOG" | ${FILTER} || true
            echo "[debug] sudo debug log (tail):"
            ${FILTER} "$SUDO_DEBUG_LOG" || true
        fi
        if [[ -f "$PLUGIN_DEBUG_LOG" ]]; then
            echo "[debug] plugin debug log:"
            tail -n 200 "$PLUGIN_DEBUG_LOG" || true
        fi
        if command -v python3 >/dev/null; then
            echo "[debug] plugin struct check:"
            PLUGIN_LIB="$PLUGIN_LIB" python3 - <<'PY' || true
import ctypes
import os

path = os.environ.get("PLUGIN_LIB", "")
if not path:
    print("  PLUGIN_LIB not set")
    raise SystemExit(0)
try:
    lib = ctypes.CDLL(path)
except OSError as e:
    print(f"  dlopen failed: {e}")
    raise SystemExit(0)

class PolicyPlugin(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("version", ctypes.c_uint),
        ("open", ctypes.c_void_p),
        ("close", ctypes.c_void_p),
        ("show_version", ctypes.c_void_p),
        ("check_policy", ctypes.c_void_p),
        ("list", ctypes.c_void_p),
        ("validate", ctypes.c_void_p),
        ("invalidate", ctypes.c_void_p),
        ("init_session", ctypes.c_void_p),
        ("register_hooks", ctypes.c_void_p),
        ("deregister_hooks", ctypes.c_void_p),
        ("event_alloc", ctypes.c_void_p),
    ]

class ApprovalPlugin(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("version", ctypes.c_uint),
        ("open", ctypes.c_void_p),
        ("close", ctypes.c_void_p),
        ("check", ctypes.c_void_p),
        ("show_version", ctypes.c_void_p),
    ]

def dump(label, sym_name, struct_cls):
    try:
        inst = struct_cls.in_dll(lib, sym_name)
    except ValueError as e:
        print(f"  {label}: missing symbol {sym_name}: {e}")
        return
    addr = ctypes.addressof(inst)
    print(f"  {label}: addr=0x{addr:x} size={ctypes.sizeof(struct_cls)} type={inst.type} version=0x{inst.version:08x}")
    if sym_name == "policy":
        print("    open={0} close={1} show_version={2}".format(inst.open, inst.close, inst.show_version))
        print("    check_policy={0} list={1} validate={2}".format(inst.check_policy, inst.list, inst.validate))
        print("    invalidate={0} init_session={1}".format(inst.invalidate, inst.init_session))
        print("    register_hooks={0} deregister_hooks={1} event_alloc={2}".format(inst.register_hooks, inst.deregister_hooks, inst.event_alloc))
    else:
        print("    open={0} close={1} check={2} show_version={3}".format(inst.open, inst.close, inst.check, inst.show_version))

print(f"  plugin: {path}")
dump("policy", "policy", PolicyPlugin)
dump("approval", "approval", ApprovalPlugin)
PY
        fi
        echo "[debug] sudo conf"
        grep -v '^#' "${SUDO_CONF}" | grep -v '^$' | uniq
    } >&2
}

write_sudo_conf_base() {
    local mode="$1"
    local dest="$2"
    if [[ -f "$SUDO_CONF_BACKUP" ]]; then
        awk -v mode="$mode" '
            $1 == "Plugin" {
                if (mode == "approval" && $2 == "approval") {
                    next
                }
                if (mode == "policy" && $2 == "policy") {
                    next
                }
            }
            { print }
        ' "$SUDO_CONF_BACKUP" > "$dest"
    else
        : > "$dest"
    fi
}

append_debug_lines() {
    local dest="$1"
    if [[ "$DEBUG" != "1" ]]; then
        return
    fi
    cat >> "$dest" <<EOF_SUDO_DEBUG
Debug sudo $SUDO_DEBUG_LOG all@debug
Debug $PLUGIN_LIB $PLUGIN_DEBUG_LOG all@debug
Debug $PLUGIN_BASENAME $PLUGIN_DEBUG_LOG all@debug
EOF_SUDO_DEBUG
}

run_sudo() {
    if [[ "$INTERACTIVE" == "1" ]]; then
        sudo "$@"
    else
        sudo -n "$@"
    fi
}

run_sudo_version() {
    sudo -V
}

run_privileged() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    else
        run_sudo "$@"
    fi
}

cleanup() {
    if [[ -f "$SUDO_CONF_BACKUP" ]]; then
        run_privileged cp "$SUDO_CONF_BACKUP" "$SUDO_CONF"
    else
        run_privileged rm -f "$SUDO_CONF"
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

if ! command -v sudo >/dev/null; then
    echo "sudo not found" >&2
    exit 1
fi

if ! command -v openssl >/dev/null; then
    echo "openssl not found" >&2
    exit 1
fi

if ! command -v python3 >/dev/null; then
    echo "python3 not found" >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "run this test as root (e.g. sudo -E $0) to ensure sudo.conf can be restored after expiry" >&2
    exit 1
fi

if [[ "$DEBUG" == "1" ]]; then
    DEBUG_OPT=" debug=1"
fi

if [[ ! -f "$PLUGIN_LIB" ]]; then
    log "plugin not found, building it"
    if [[ "$PLUGIN_LIB" == *"sudo_awesome_jwt_rust.so"* ]]; then
        (cd "$ROOT_DIR/rust" && cargo build --release)
    else
        (cd "$ROOT_DIR" && make)
    fi
fi

if [[ ! -f "$PLUGIN_LIB" ]]; then
    echo "plugin library not found: $PLUGIN_LIB" >&2
    exit 1
fi


if [[ -f "$SUDO_CONF" ]]; then
    log "backing up sudo.conf"
    run_privileged cp "$SUDO_CONF" "$SUDO_CONF_BACKUP"
fi

log "generating RSA keypair"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_PRIV" >/dev/null 2>&1
openssl rsa -in "$KEY_PRIV" -pubout -out "$KEY_PUB" >/dev/null 2>&1

log "writing test config"
cat > "$CONFIG_FILE" <<'EOF_CONFIG'
# autogenerated test config
token_file = TOKEN_FILE_PLACEHOLDER
public_key = KEY_PUB_PLACEHOLDER
issuer = "test-issuer"
audience = "test-audience"
scope = "sudo"
require_tty = false
max_ttl = 30
EOF_CONFIG

sed -i "s|TOKEN_FILE_PLACEHOLDER|$TOKEN_FILE|" "$CONFIG_FILE"
sed -i "s|KEY_PUB_PLACEHOLDER|$KEY_PUB|" "$CONFIG_FILE"

make_jwt() {
    local ttl="$1"
    log_err "generating JWT (ttl=${ttl}s)"
    KEY_PRIV="$KEY_PRIV" TTL_SECS="$ttl" JWT_SUB="$JWT_SUB" JWT_CMDS="$JWT_CMDS" JWT_RUNAS_USERS="$JWT_RUNAS_USERS" JWT_SETENV_RUNAS="$JWT_SETENV_RUNAS" JWT_INCLUDE_RUNAS_IDS="$JWT_INCLUDE_RUNAS_IDS" JWT_INCLUDE_RUNAS_ENTRIES="$JWT_INCLUDE_RUNAS_ENTRIES" JWT_FAKE_COUNT="$JWT_FAKE_COUNT" JWT_FAKE_USER="$JWT_FAKE_USER" JWT_FAKE_UID="$JWT_FAKE_UID" JWT_FAKE_GID="$JWT_FAKE_GID" JWT_RUNAS_GROUP="$JWT_RUNAS_GROUP" python3 - <<'PY'
import base64
import json
import os
import subprocess
import time

key = os.environ["KEY_PRIV"]
ttl = int(os.environ["TTL_SECS"])
sub = os.environ.get("JWT_SUB", "")
cmds_raw = os.environ.get("JWT_CMDS", "")
runas_raw = os.environ.get("JWT_RUNAS_USERS", "")
setenv_raw = os.environ.get("JWT_SETENV_RUNAS", "")
include_ids_raw = os.environ.get("JWT_INCLUDE_RUNAS_IDS", "1").strip().lower()
include_ids = include_ids_raw not in ("0", "false", "no")
include_runas_entries_raw = os.environ.get("JWT_INCLUDE_RUNAS_ENTRIES", "1").strip().lower()
include_runas_entries = include_runas_entries_raw not in ("0", "false", "no")
fake_count = int(os.environ.get("JWT_FAKE_COUNT", "0") or 0)
fake_user = os.environ.get("JWT_FAKE_USER", "")
fake_uid = os.environ.get("JWT_FAKE_UID", "")
fake_gid = os.environ.get("JWT_FAKE_GID", "")
runas_group = os.environ.get("JWT_RUNAS_GROUP", "").strip()
now = int(time.time())
header = {"alg": "RS256", "typ": "JWT"}
cmds = [line for line in cmds_raw.splitlines() if line]
runas_entries = []
for line in runas_raw.splitlines():
    if not line:
        continue
    parts = line.split(":", 2)
    user = parts[0]
    uid = parts[1] if len(parts) > 1 else ""
    gid = parts[2] if len(parts) > 2 else ""
    runas_entries.append((user, uid, gid))
if not runas_entries:
    runas_entries = [("", "", "")]
setenv_entries = []
for line in setenv_raw.splitlines():
    if not line:
        continue
    parts = line.split(":", 2)
    user = parts[0]
    uid = parts[1] if len(parts) > 1 else ""
    gid = parts[2] if len(parts) > 2 else ""
    setenv_entries.append((user, uid, gid))

cmds_payload = []
for i in range(fake_count):
    entry = {"path": f"/tmp/sudo-awesome-jwt-fake-{i}"}
    if fake_user:
        entry["runas_user"] = fake_user
    if include_ids and fake_uid:
        try:
            entry["runas_uid"] = int(fake_uid)
        except ValueError:
            pass
    if include_ids and fake_gid:
        try:
            entry["runas_gid"] = int(fake_gid)
        except ValueError:
            pass
    if runas_group:
        entry["runas_group"] = runas_group
    cmds_payload.append(entry)
for cmd in cmds:
    if include_runas_entries:
        for user, uid, gid in runas_entries:
            entry = {"path": cmd}
            if user:
                entry["runas_user"] = user
            if include_ids and uid:
                try:
                    entry["runas_uid"] = int(uid)
                except ValueError:
                    pass
            if include_ids and gid:
                try:
                    entry["runas_gid"] = int(gid)
                except ValueError:
                    pass
            if runas_group:
                entry["runas_group"] = runas_group
            cmds_payload.append(entry)
    for user, uid, gid in setenv_entries:
        entry = {"path": cmd, "setenv": True}
        if user:
            entry["runas_user"] = user
        if include_ids and uid:
            try:
                entry["runas_uid"] = int(uid)
            except ValueError:
                pass
        if include_ids and gid:
            try:
                entry["runas_gid"] = int(gid)
            except ValueError:
                pass
        if runas_group:
            entry["runas_group"] = runas_group
        cmds_payload.append(entry)

payload = {
    "iss": "test-issuer",
    "aud": "test-audience",
    "scope": "sudo",
    "iat": now,
    "exp": now + ttl,
    "sub": sub,
    "cmds": cmds_payload,
}

def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")

signing_input = b".".join([
    b64url(json.dumps(header, separators=(",", ":")).encode()),
    b64url(json.dumps(payload, separators=(",", ":")).encode()),
])

sig = subprocess.check_output([
    "openssl", "dgst", "-sha256", "-sign", key
], input=signing_input)

jwt = b".".join([signing_input, b64url(sig)])
print(jwt.decode())
PY
}

write_token() {
    local ttl="$1"
    local token
    token=$(make_jwt "$ttl")
    log "writing token to $TOKEN_FILE"
    printf '%s' "$token" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
}

set_sudo_conf_approval() {
    log "configuring sudo.conf for approval plugin"
    write_sudo_conf_base approval "$WORKDIR/sudo.conf"
    cat >> "$WORKDIR/sudo.conf" <<'EOF_SUDO_APPROVAL'
Plugin approval PLUGIN_PATH_PLACEHOLDER config=CONFIG_PATH_PLACEHOLDERDEBUG_OPT_PLACEHOLDER
EOF_SUDO_APPROVAL
    sed -i "s|PLUGIN_PATH_PLACEHOLDER|$PLUGIN_LIB|" "$WORKDIR/sudo.conf"
    sed -i "s|CONFIG_PATH_PLACEHOLDER|$CONFIG_FILE|" "$WORKDIR/sudo.conf"
    sed -i "s|DEBUG_OPT_PLACEHOLDER|$DEBUG_OPT|" "$WORKDIR/sudo.conf"
    append_debug_lines "$WORKDIR/sudo.conf"
    run_privileged cp "$WORKDIR/sudo.conf" "$SUDO_CONF"
}

set_sudo_conf_policy() {
    log "configuring sudo.conf for policy plugin"
    write_sudo_conf_base policy "$WORKDIR/sudo.conf"
    cat >> "$WORKDIR/sudo.conf" <<'EOF_SUDO_POLICY'
Plugin policy PLUGIN_PATH_PLACEHOLDER config=CONFIG_PATH_PLACEHOLDERDEBUG_OPT_PLACEHOLDER
EOF_SUDO_POLICY
    sed -i "s|PLUGIN_PATH_PLACEHOLDER|$PLUGIN_LIB|" "$WORKDIR/sudo.conf"
    sed -i "s|CONFIG_PATH_PLACEHOLDER|$CONFIG_FILE|" "$WORKDIR/sudo.conf"
    sed -i "s|DEBUG_OPT_PLACEHOLDER|$DEBUG_OPT|" "$WORKDIR/sudo.conf"
    append_debug_lines "$WORKDIR/sudo.conf"
    run_privileged cp "$WORKDIR/sudo.conf" "$SUDO_CONF"
}

run_once() {
    local plugin_type="$1"
    log "testing $plugin_type plugin"

    if [[ "$plugin_type" == "approval" ]]; then
        set_sudo_conf_approval
    else
        set_sudo_conf_policy
    fi

    log "running sudo -V ($plugin_type)"
    if ! output=$(run_sudo_version 2>&1); then
        echo "$output" >&2
        dump_debug
        echo "expected sudo -V to succeed for $plugin_type" >&2
        exit 1
    fi

    log "running sudo -l ($plugin_type)"
    if ! output=$(run_sudo -l 2>&1); then
        echo "$output" >&2
        dump_debug
        echo "expected sudo -l to succeed for $plugin_type" >&2
        exit 1
    fi

    local -a token_files=()
    local token_idx=0
    for cmd in "${TEST_COMMANDS[@]}"; do
        local variants=(
            "with-ids:1:0"
            "user-only:0:0"
            "with-fakes:1:3"
        )
        for variant in "${variants[@]}"; do
            IFS=':' read -r variant_label include_ids fake_count <<< "$variant"
            if ! prepare_jwt_env "$cmd" "root" "$ROOT_UID" "$ROOT_GID" 0 "$include_ids" "$fake_count"; then
                dump_debug
                echo "failed to prepare JWT for $plugin_type ($cmd) [$variant_label]" >&2
                exit 1
            fi
            write_token "$TTL_SECS"
            if [[ "$variant_label" == "with-ids" ]]; then
                local token_copy="$WORKDIR/token.${plugin_type}.${token_idx}"
                cp "$TOKEN_FILE" "$token_copy"
                token_files+=("$token_copy")
                token_idx=$((token_idx + 1))
            fi
            log "running sudo command with fresh token ($cmd) [$variant_label]"
            if ! output=$(run_sudo "$cmd" 2>&1); then
                echo "$output" >&2
                dump_debug
                echo "expected sudo to succeed for $plugin_type with fresh token ($cmd) [$variant_label]" >&2
                exit 1
            fi
        done
    done

    local deny_token="$WORKDIR/token.${plugin_type}.deny"
    if [[ -n "$DENY_CMD" && -n "$DENY_CMD_RESOLVED" ]]; then
        if ! prepare_jwt_env "$ID_CMD" "root" "$ROOT_UID" "$ROOT_GID" 0 1 0 1; then
            dump_debug
            echo "failed to prepare JWT for deny test ($plugin_type)" >&2
            exit 1
        fi
        write_token "$TTL_SECS"
        cp "$TOKEN_FILE" "$deny_token"
        log "running sudo command not in claim (fresh) ($DENY_CMD_RESOLVED)"
        if output=$(run_sudo "$DENY_CMD_RESOLVED" 2>&1); then
            echo "$output" >&2
            dump_debug
            echo "expected sudo to fail for $plugin_type when command not in claim (fresh)" >&2
            exit 1
        fi
    fi

    if [[ -n "$RUNAS_USER" && -n "$RUNAS_UID" ]]; then
        local runas_variants=(
            "with-ids:1:0"
            "user-only:0:0"
            "with-fakes:1:3"
        )
        for variant in "${runas_variants[@]}"; do
            IFS=':' read -r variant_label include_ids fake_count <<< "$variant"
            if ! prepare_jwt_env "$ID_CMD" "$RUNAS_USER" "$RUNAS_UID" "$RUNAS_GID" 0 "$include_ids" "$fake_count"; then
                dump_debug
                echo "failed to prepare JWT for runas user ($RUNAS_USER) ($plugin_type) [$variant_label]" >&2
                exit 1
            fi
            write_token "$TTL_SECS"
            log "running sudo command with runas user ($RUNAS_USER) ($plugin_type) [$variant_label]"
            runas_err="$WORKDIR/runas.stderr"
            if ! output=$(run_sudo -u "$RUNAS_USER" "$ID_CMD" -u 2>"$runas_err"); then
                cat "$runas_err" >&2 || true
                dump_debug
                echo "expected sudo -u $RUNAS_USER to succeed for $plugin_type [$variant_label]" >&2
                exit 1
            fi
            output_trimmed=$(echo "$output" | tr -d '[:space:]')
            if [[ "$output_trimmed" != "$RUNAS_UID" ]]; then
                cat "$runas_err" >&2 || true
                echo "$output" >&2
                dump_debug
                echo "expected sudo -u $RUNAS_USER to run as uid $RUNAS_UID for $plugin_type [$variant_label]" >&2
                exit 1
            fi
        done
    fi

    if [[ -n "$MISMATCH_RUNAS_USER" ]]; then
        if ! prepare_jwt_env "$ID_CMD" "root" "$ROOT_UID" "$ROOT_GID" 0 1 0 1; then
            dump_debug
            echo "failed to prepare JWT for mismatch runas user ($plugin_type)" >&2
            exit 1
        fi
        write_token "$TTL_SECS"
        log "running sudo command with non-matching runas user ($MISMATCH_RUNAS_USER) ($plugin_type)"
        if output=$(run_sudo -u "$MISMATCH_RUNAS_USER" "$ID_CMD" -u 2>&1); then
            echo "$output" >&2
            dump_debug
            echo "expected sudo -u $MISMATCH_RUNAS_USER to fail for $plugin_type (runas mismatch)" >&2
            exit 1
        fi
    fi

    if [[ -n "$RUNAS_GROUP" && -n "$RUNAS_GROUP_GID" ]]; then
        local group_variants=(
            "with-ids:1:0"
            "user-only:0:0"
            "with-fakes:1:3"
        )
        local group_claims=(
            "$RUNAS_GROUP"
        )
        for claim_group in "${group_claims[@]}"; do
            for variant in "${group_variants[@]}"; do
                IFS=':' read -r variant_label include_ids fake_count <<< "$variant"
                if ! prepare_jwt_env "$ID_CMD" "root" "$ROOT_UID" "$ROOT_GID" 0 "$include_ids" "$fake_count" 1 "$claim_group"; then
                    dump_debug
                    echo "failed to prepare JWT for runas group ($RUNAS_GROUP) ($plugin_type) [$variant_label]" >&2
                    exit 1
                fi
                write_token "$TTL_SECS"
                log "running sudo command with runas group ($RUNAS_GROUP) ($plugin_type) [$variant_label]"
                group_err="$WORKDIR/runas_group.stderr"
                if ! output=$(run_sudo -g "$RUNAS_GROUP" "$ID_CMD" -g 2>"$group_err"); then
                    cat "$group_err" >&2 || true
                    dump_debug
                    echo "expected sudo -g $RUNAS_GROUP to succeed for $plugin_type [$variant_label]" >&2
                    exit 1
                fi
                output_trimmed=$(echo "$output" | tr -d '[:space:]')
                if [[ "$output_trimmed" != "$RUNAS_GROUP_GID" ]]; then
                    cat "$group_err" >&2 || true
                    echo "$output" >&2
                    dump_debug
                    echo "expected sudo -g $RUNAS_GROUP to run as gid $RUNAS_GROUP_GID for $plugin_type [$variant_label]" >&2
                    exit 1
                fi
            done
        done
    fi

    if [[ -n "$RUNAS_GROUP" && -n "$MISMATCH_RUNAS_GROUP" ]]; then
        if ! prepare_jwt_env "$ID_CMD" "root" "$ROOT_UID" "$ROOT_GID" 0 1 0 1 "$RUNAS_GROUP"; then
            dump_debug
            echo "failed to prepare JWT for mismatch runas group ($plugin_type)" >&2
            exit 1
        fi
        write_token "$TTL_SECS"
        log "running sudo command with non-matching runas group ($MISMATCH_RUNAS_GROUP) ($plugin_type)"
        if output=$(run_sudo -g "$MISMATCH_RUNAS_GROUP" "$ID_CMD" -g 2>&1); then
            echo "$output" >&2
            dump_debug
            echo "expected sudo -g $MISMATCH_RUNAS_GROUP to fail for $plugin_type (runas group mismatch)" >&2
            exit 1
        fi
    fi

    if [[ "$plugin_type" == "approval" && -n "$ALLOW_SETENV_USER" && -n "$ALLOW_SETENV_UID" ]]; then
        local setenv_variants=(
            "with-ids:1:0"
            "user-only:0:0"
            "with-fakes:1:3"
        )
        for variant in "${setenv_variants[@]}"; do
            IFS=':' read -r variant_label include_ids fake_count <<< "$variant"
            if ! prepare_jwt_env "$ID_CMD" "$ALLOW_SETENV_USER" "$ALLOW_SETENV_UID" "$ALLOW_SETENV_GID" 1 "$include_ids" "$fake_count" 0; then
                dump_debug
                echo "failed to prepare JWT for setenv user ($ALLOW_SETENV_USER) [$variant_label]" >&2
                exit 1
            fi
            write_token "$TTL_SECS"
            log "running sudo command with SETENV ($ALLOW_SETENV_USER) ($plugin_type) [$variant_label]"
            setenv_err="$WORKDIR/setenv.stderr"
            if ! output=$(run_sudo -E -u "$ALLOW_SETENV_USER" "$ID_CMD" -u 2>"$setenv_err"); then
                cat "$setenv_err" >&2 || true
                dump_debug
                echo "expected sudo -E -u $ALLOW_SETENV_USER to succeed for $plugin_type [$variant_label]" >&2
                exit 1
            fi
            output_trimmed=$(echo "$output" | tr -d '[:space:]')
            if [[ "$output_trimmed" != "$ALLOW_SETENV_UID" ]]; then
                cat "$setenv_err" >&2 || true
                echo "$output" >&2
                dump_debug
                echo "expected sudo -E -u $ALLOW_SETENV_USER to run as uid $ALLOW_SETENV_UID for $plugin_type [$variant_label]" >&2
                exit 1
            fi
        done

        if command -v "$PRINTENV_CMD" >/dev/null 2>&1; then
            export "$SETENV_TEST_VAR"="$SETENV_TEST_VALUE"
            for variant in "${setenv_variants[@]}"; do
                IFS=':' read -r variant_label include_ids fake_count <<< "$variant"
                if ! prepare_jwt_env "$PRINTENV_CMD" "$ALLOW_SETENV_USER" "$ALLOW_SETENV_UID" "$ALLOW_SETENV_GID" 1 "$include_ids" "$fake_count" 0; then
                    dump_debug
                    echo "failed to prepare JWT for setenv printenv ($ALLOW_SETENV_USER) [$variant_label]" >&2
                    exit 1
                fi
                write_token "$TTL_SECS"
                log "running sudo printenv with SETENV ($ALLOW_SETENV_USER) ($plugin_type) [$variant_label]"
                setenv_err="$WORKDIR/setenv.stderr"
                if ! output=$(run_sudo -E -u "$ALLOW_SETENV_USER" "$PRINTENV_CMD" "$SETENV_TEST_VAR" 2>"$setenv_err"); then
                    cat "$setenv_err" >&2 || true
                    dump_debug
                    echo "expected sudo -E -u $ALLOW_SETENV_USER printenv to succeed for $plugin_type [$variant_label]" >&2
                    exit 1
                fi
                output_trimmed=$(echo "$output" | tr -d '[:space:]')
                if [[ "$output_trimmed" != "$SETENV_TEST_VALUE" ]]; then
                    echo "$output" >&2
                    dump_debug
                    echo "expected sudo -E -u $ALLOW_SETENV_USER printenv to return $SETENV_TEST_VALUE for $plugin_type [$variant_label]" >&2
                    exit 1
                fi
            done
        fi
    fi

    log "waiting $WAIT_SECS seconds for token expiry"
    sleep "$WAIT_SECS"

    for i in "${!TEST_COMMANDS[@]}"; do
        cmd="${TEST_COMMANDS[$i]}"
        if [[ -n "${token_files[$i]:-}" ]]; then
            cp "${token_files[$i]}" "$TOKEN_FILE"
        fi
        log "running sudo command after expiry ($cmd)"
        if output=$(run_sudo "$cmd" 2>&1); then
            echo "$output" >&2
            dump_debug
            echo "expected sudo to fail for $plugin_type after token expiry ($cmd)" >&2
            exit 1
        fi
    done

    if [[ -n "$DENY_CMD" && -n "$DENY_CMD_RESOLVED" && -f "$deny_token" ]]; then
        cp "$deny_token" "$TOKEN_FILE"
        log "running sudo command not in claim (expired) ($DENY_CMD_RESOLVED)"
        if output=$(run_sudo "$DENY_CMD_RESOLVED" 2>&1); then
            echo "$output" >&2
            dump_debug
            echo "expected sudo to fail for $plugin_type when command not in claim (expired)" >&2
            exit 1
        fi
    fi
}

run_once approval
run_once policy

log "all plugin tests passed"
