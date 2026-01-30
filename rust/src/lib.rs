use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::hash::MessageDigest;
use serde_json::Value;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::os::unix::fs::MetadataExt;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use std::path::PathBuf;

const SUDO_API_VERSION_MAJOR: u32 = 1;
const SUDO_API_VERSION_MINOR: u32 = 22;
const SUDO_API_VERSION: u32 = (SUDO_API_VERSION_MAJOR << 16) | SUDO_API_VERSION_MINOR;

const SUDO_POLICY_PLUGIN: u32 = 1;
const SUDO_APPROVAL_PLUGIN: u32 = 4;
const SUDO_CONV_ERROR_MSG: c_int = 0x0003;

const DEFAULT_CONFIG_PATH: &str = "/usr/local/etc/sudo_awesome_jwt.conf";
const DEFAULT_SCOPE: &str = "sudo";
const MAX_TOKEN_BYTES: u64 = 16 * 1024;
const MAX_AUDIENCE_BYTES: u64 = 1024;
const MAX_ALLOWLIST_BYTES: u64 = 4096;
const CLOCK_SKEW_SECONDS: i64 = 60;

#[repr(C)]
pub struct approval_plugin {
    plugin_type: c_uint,
    version: c_uint,
    open: Option<extern "C" fn(c_uint, SudoConvT, SudoPrintfT, *const *const c_char, *const *const c_char, c_int, *const *const c_char, *const *const c_char, *const *const c_char, *mut *const c_char) -> c_int>,
    close: Option<extern "C" fn()>,
    check: Option<extern "C" fn(*const *const c_char, *const *const c_char, *const *const c_char, *mut *const c_char) -> c_int>,
    show_version: Option<extern "C" fn(c_int) -> c_int>,
}

#[repr(C)]
pub struct policy_plugin {
    plugin_type: c_uint,
    version: c_uint,
    open: Option<extern "C" fn(c_uint, SudoConvT, SudoPrintfT, *const *const c_char, *const *const c_char, *const *const c_char, *const *const c_char, *mut *const c_char) -> c_int>,
    close: Option<extern "C" fn(c_int, c_int)>,
    show_version: Option<extern "C" fn(c_int) -> c_int>,
    check_policy: Option<extern "C" fn(c_int, *const *const c_char, *const *const c_char, *mut *const *const c_char, *mut *const *const c_char, *mut *const *const c_char, *mut *const c_char) -> c_int>,
    list: Option<extern "C" fn(c_int, *const *const c_char, c_int, *const c_char, *mut *const c_char) -> c_int>,
    validate: Option<extern "C" fn(*mut *const c_char) -> c_int>,
    invalidate: Option<extern "C" fn(c_int)>,
    init_session: Option<extern "C" fn(*mut libc::passwd, *mut *const *const c_char, *mut *const c_char) -> c_int>,
    register_hooks: Option<extern "C" fn(c_int, *mut libc::c_void)>,
    deregister_hooks: Option<extern "C" fn(c_int, *mut libc::c_void)>,
    event_alloc: Option<extern "C" fn() -> *mut libc::c_void>,
}

pub type SudoConvT = Option<extern "C" fn(c_int, *const libc::c_void, *mut libc::c_void, *mut libc::c_void) -> c_int>;
pub type SudoPrintfT = Option<extern "C" fn(c_int, *const c_char, ...) -> c_int>;

#[derive(Default)]
struct State {
    config: Option<Config>,
    user: Option<String>,
    uid: Option<u32>,
    tty: Option<String>,
    last_err: Option<CString>,
    command_info: Option<Vec<CString>>,
    command_info_ptrs: Option<Vec<usize>>,
    env_ptrs: Option<Vec<usize>>,
    sudo_printf: SudoPrintfT,
}

#[derive(Clone)]
struct Config {
    token_file: String,
    public_key: String,
    issuer: String,
    audience: String,
    scope: String,
    host: Option<String>,
    max_ttl: i64,
    require_jwt: bool,
    require_tty: bool,
    only_user: Option<String>,
    only_uid: Option<u32>,
    command_allowlist: Vec<String>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static DEBUG_OVERRIDE: AtomicBool = AtomicBool::new(false);

fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    let mutex = STATE.get_or_init(|| Mutex::new(State::default()));
    let mut state = mutex.lock().expect("state lock");
    f(&mut state)
}

fn set_err(state: &mut State, errstr: *mut *const c_char, msg: &str) {
    state.last_err = CString::new(msg).ok();
    if let Some(ref cstr) = state.last_err {
        unsafe {
            if !errstr.is_null() {
                *errstr = cstr.as_ptr();
            }
        }
    }
}

fn log_error(state: &State, prefix: &str, msg: &str) {
    let Some(printf_fn) = state.sudo_printf else { return; };
    let message = format!("{prefix}: {msg}\n");
    let fmt = CString::new("%s").ok();
    let msg_c = CString::new(message).ok();
    if let (Some(fmt), Some(msg_c)) = (fmt, msg_c) {
        printf_fn(SUDO_CONV_ERROR_MSG, fmt.as_ptr(), msg_c.as_ptr());
    }
}

fn debug_enabled() -> bool {
    if DEBUG_OVERRIDE.load(Ordering::Relaxed) {
        return true;
    }
    match env::var("SUDO_AWESOME_JWT_DEBUG") {
        Ok(val) => !val.is_empty() && val != "0",
        Err(_) => false,
    }
}

fn debug_log(msg: &str) {
    if debug_enabled() {
        eprintln!("sudo-awesome-jwt-policy: {msg}");
    }
}

fn parse_debug_options(plugin_options: *const *const c_char) {
    DEBUG_OVERRIDE.store(false, Ordering::Relaxed);
    unsafe {
        if plugin_options.is_null() {
            return;
        }
        let mut idx = 0;
        loop {
            let ptr = *plugin_options.add(idx);
            if ptr.is_null() {
                break;
            }
            let s = CStr::from_ptr(ptr).to_string_lossy();
            if s == "debug" {
                DEBUG_OVERRIDE.store(true, Ordering::Relaxed);
            } else if let Some(val) = s.strip_prefix("debug=") {
                let enable = matches!(val, "1" | "true" | "yes");
                DEBUG_OVERRIDE.store(enable, Ordering::Relaxed);
            }
            idx += 1;
        }
    }
}

fn debug_dump_command_info(entries: &[CString]) {
    if !debug_enabled() {
        return;
    }
    eprintln!("sudo-awesome-jwt-policy: command_info dump:");
    for entry in entries {
        eprintln!("  {}", entry.to_string_lossy());
    }
}

fn build_command_info(argv: *const *const c_char) -> (Vec<CString>, Vec<usize>) {
    let cmd = unsafe {
        if !argv.is_null() && !(*argv).is_null() {
            CStr::from_ptr(*argv).to_string_lossy().into_owned()
        } else {
            String::new()
        }
    };
    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("/"))
        .to_string_lossy()
        .into_owned();
    let mut entries = Vec::new();
    entries.push(CString::new(format!("command={cmd}")).unwrap());
    entries.push(CString::new(format!("command_path={cmd}")).unwrap());
    entries.push(CString::new("runas_user=root").unwrap());
    entries.push(CString::new("runas_uid=0").unwrap());
    entries.push(CString::new("runas_gid=0").unwrap());
    entries.push(CString::new(format!("cwd={cwd}")).unwrap());
    let mut ptrs: Vec<usize> = entries.iter().map(|c| c.as_ptr() as usize).collect();
    ptrs.push(0);
    (entries, ptrs)
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn expand_vars(input: &str, user: Option<&str>, uid: Option<u32>) -> Option<String> {
    if !input.contains("${") {
        return None;
    }
    let uid_str = uid.map(|u| u.to_string());
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut key = String::new();
            while let Some(&c) = chars.peek() {
                chars.next();
                if c == '}' {
                    break;
                }
                key.push(c);
            }
            match key.as_str() {
                "user" if user.is_some() => {
                    out.push_str(user.unwrap());
                    changed = true;
                    continue;
                }
                "uid" if uid_str.is_some() => {
                    out.push_str(uid_str.as_ref().unwrap());
                    changed = true;
                    continue;
                }
                _ => {
                    out.push_str("${");
                    out.push_str(&key);
                    out.push('}');
                    continue;
                }
            }
        }
        out.push(ch);
    }

    if changed {
        Some(out)
    } else {
        None
    }
}

fn parse_allowlist(text: &str, allow_expand: bool, user: Option<&str>, uid: Option<u32>) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.split(|c: char| c == ',' || c == '\n' || c == '\r') {
        let mut entry = raw.trim().to_string();
        if entry.is_empty() {
            continue;
        }
        let mut quote_char = None;
        if (entry.starts_with('\"') && entry.ends_with('\"')) || (entry.starts_with('\'') && entry.ends_with('\'')) {
            quote_char = entry.chars().next();
            entry = entry[1..entry.len() - 1].trim().to_string();
        }
        if allow_expand && quote_char != Some('\'') {
            if let Some(expanded) = expand_vars(&entry, user, uid) {
                entry = expanded;
            }
        }
        if !entry.is_empty() {
            out.push(entry);
        }
    }
    out
}

fn parse_config(path: &str, user: Option<&str>, uid: Option<u32>) -> Result<Config, String> {
    let data = std::fs::read_to_string(path).map_err(|_| "unable to open policy config".to_string())?;
    let mut cfg = Config {
        token_file: String::new(),
        public_key: String::new(),
        issuer: String::new(),
        audience: String::new(),
        scope: DEFAULT_SCOPE.to_string(),
        host: None,
        max_ttl: 300,
        require_jwt: true,
        require_tty: false,
        only_user: None,
        only_uid: None,
        command_allowlist: Vec::new(),
    };

    for raw in data.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue; };
        let key = k.trim();
        let mut val = v.trim().to_string();
        let mut quote_char = None;
        if (val.starts_with('"') && val.ends_with('"')) || (val.starts_with('\'') && val.ends_with('\'')) {
            quote_char = val.chars().next();
            val = val[1..val.len() - 1].to_string();
        } else if let Some(idx) = val.find('#') {
            val = val[..idx].trim().to_string();
        }
        if val.is_empty() {
            continue;
        }

        if quote_char != Some('\'') {
            if let Some(expanded) = expand_vars(&val, user, uid) {
                val = expanded;
            }
        }

        match key.to_ascii_lowercase().as_str() {
            "token_file" => cfg.token_file = val,
            "public_key" => cfg.public_key = val,
            "issuer" => cfg.issuer = val,
            "audience" => {
                if quote_char.is_none() && val.starts_with('/') {
                    cfg.audience = read_text_file(&val, MAX_AUDIENCE_BYTES)?;
                } else {
                    cfg.audience = val;
                }
            }
            "scope" => cfg.scope = val,
            "host" => cfg.host = Some(val),
            "max_ttl" => {
                if let Ok(num) = val.parse::<i64>() {
                    cfg.max_ttl = num;
                }
            }
            "require_jwt" => {
                if let Some(b) = parse_bool(&val.to_ascii_lowercase()) {
                    cfg.require_jwt = b;
                }
            }
            "require_tty" => {
                if let Some(b) = parse_bool(&val.to_ascii_lowercase()) {
                    cfg.require_tty = b;
                }
            }
            "only_user" => cfg.only_user = Some(val),
            "only_uid" => {
                if let Ok(uid) = val.parse::<u32>() {
                    cfg.only_uid = Some(uid);
                }
            }
            "command_allowlist" | "command_allowlist_csv" => {
                let allow_expand = quote_char != Some('\'');
                if quote_char.is_none() && val.starts_with('/') {
                    let text = read_text_file_labeled(&val, MAX_ALLOWLIST_BYTES, "command allowlist")?;
                    cfg.command_allowlist.extend(parse_allowlist(&text, allow_expand, user, uid));
                } else {
                    cfg.command_allowlist.extend(parse_allowlist(&val, allow_expand, user, uid));
                }
            }
            _ => {}
        }
    }

    if cfg.token_file.is_empty() || cfg.public_key.is_empty() || cfg.issuer.is_empty() || cfg.audience.is_empty() {
        return Err("missing required config key".to_string());
    }

    Ok(cfg)
}

fn read_text_file_labeled(path: &str, max_len: u64, label: &str) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|_| format!("unable to open {label} file"))?;
    if !meta.is_file() {
        return Err(format!("{label} file is not regular"));
    }
    if (meta.mode() & 0o22) != 0 {
        return Err(format!("{label} file is writable by group or others"));
    }
    if meta.len() == 0 || meta.len() > max_len {
        return Err(format!("{label} file size invalid"));
    }
    let data = std::fs::read_to_string(path).map_err(|_| format!("unable to read {label} file"))?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} file empty"));
    }
    Ok(trimmed.to_string())
}

fn read_text_file(path: &str, max_len: u64) -> Result<String, String> {
    read_text_file_labeled(path, max_len, "audience")
}

// replaced by parse_allowlist(text, allow_expand, user, uid)

fn read_token(path: &str) -> Result<String, String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err("token missing".to_string());
            }
            return Err("unable to open token file".to_string());
        }
    };
    if (meta.mode() & 0o22) != 0 {
        return Err("token file is writable by group or others".to_string());
    }
    if meta.len() == 0 || meta.len() > MAX_TOKEN_BYTES {
        return Err("token file size invalid".to_string());
    }
    let data = std::fs::read_to_string(path).map_err(|_| "unable to read token".to_string())?;
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Err("empty token".to_string());
    }
    Ok(trimmed.to_string())
}

fn should_enforce_user(state: &State, cfg: &Config) -> bool {
    if let Some(ref only_user) = cfg.only_user {
        if state.user.as_deref() != Some(only_user.as_str()) {
            return false;
        }
    }
    if let Some(only_uid) = cfg.only_uid {
        if state.uid != Some(only_uid) {
            return false;
        }
    }
    true
}

fn command_from_info(command_info: *const *const c_char, run_argv: *const *const c_char) -> Option<String> {
    unsafe {
        if !command_info.is_null() {
            let mut idx = 0;
            loop {
                let ptr = *command_info.add(idx);
                if ptr.is_null() { break; }
                let s = CStr::from_ptr(ptr).to_string_lossy();
                if let Some(val) = s.strip_prefix("command=") {
                    return Some(val.to_string());
                }
                if let Some(val) = s.strip_prefix("command_path=") {
                    return Some(val.to_string());
                }
                idx += 1;
            }
        }
        if !run_argv.is_null() {
            let first = *run_argv;
            if !first.is_null() {
                return Some(CStr::from_ptr(first).to_string_lossy().to_string());
            }
        }
    }
    None
}

fn command_requires_jwt(cfg: &Config, command_info: *const *const c_char, run_argv: *const *const c_char) -> bool {
    if cfg.command_allowlist.is_empty() {
        return true;
    }
    let Some(cmd) = command_from_info(command_info, run_argv) else {
        return true;
    };
    cfg.command_allowlist.iter().any(|c| c == &cmd)
}

fn has_scope(scope_val: &Value, required: &str) -> bool {
    match scope_val {
        Value::String(s) => s.split(|c: char| c == ',' || c.is_whitespace()).any(|t| t == required),
        Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(required)),
        _ => false,
    }
}

fn aud_matches(aud_val: &Value, expected: &str) -> bool {
    match aud_val {
        Value::String(s) => s == expected,
        Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn verify_rs256(pubkey_pem: &[u8], signing: &[u8], sig: &[u8]) -> Result<bool, String> {
    let pkey = PKey::public_key_from_pem(pubkey_pem).map_err(|_| "unable to read public key".to_string())?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).map_err(|_| "signature verification failed".to_string())?;
    verifier.update(signing).map_err(|_| "signature verification failed".to_string())?;
    verifier.verify(sig).map_err(|_| "signature verification failed".to_string())
}

fn verify_eddsa(pubkey_pem: &[u8], signing: &[u8], sig: &[u8]) -> Result<bool, String> {
    let pkey = PKey::public_key_from_pem(pubkey_pem).map_err(|_| "unable to read public key".to_string())?;
    let mut verifier = Verifier::new_without_digest(&pkey).map_err(|_| "signature verification failed".to_string())?;
    verifier.verify_oneshot(sig, signing).map_err(|_| "signature verification failed".to_string())
}

fn verify_jwt(cfg: &Config, token: &str) -> Result<Value, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("token missing parts".to_string());
    }
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| "invalid header".to_string())?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| "invalid payload".to_string())?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| "invalid signature".to_string())?;

    let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| "invalid header JSON".to_string())?;
    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or_else(|| "missing alg".to_string())?;

    let signing = format!("{}.{}", parts[0], parts[1]);
    let pubkey_pem = std::fs::read(&cfg.public_key).map_err(|_| "unable to read public key".to_string())?;
    let verified = match alg {
        "RS256" => verify_rs256(&pubkey_pem, signing.as_bytes(), &sig_bytes)?,
        "EdDSA" => verify_eddsa(&pubkey_pem, signing.as_bytes(), &sig_bytes)?,
        _ => return Err("unsupported alg".to_string()),
    };
    if !verified {
        return Err("signature verification failed".to_string());
    }

    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|_| "invalid payload JSON".to_string())?;
    Ok(payload)
}

fn check_claims(cfg: &Config, payload: &Value) -> Result<(), String> {
    let iss = payload.get("iss").and_then(|v| v.as_str()).ok_or_else(|| "missing iss".to_string())?;
    if iss != cfg.issuer {
        return Err("issuer mismatch".to_string());
    }

    let aud = payload.get("aud").ok_or_else(|| "missing aud".to_string())?;
    if !aud_matches(aud, &cfg.audience) {
        return Err("audience mismatch".to_string());
    }

    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| "missing exp".to_string())?;
    let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| "missing iat".to_string())?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "time error".to_string())?.as_secs() as i64;
    if now > exp + CLOCK_SKEW_SECONDS {
        return Err("token expired".to_string());
    }
    if now + CLOCK_SKEW_SECONDS < iat {
        return Err("token issued in future".to_string());
    }

    if cfg.max_ttl > 0 {
        if exp - iat > cfg.max_ttl {
            return Err("token ttl too long".to_string());
        }
        if now - iat > cfg.max_ttl + CLOCK_SKEW_SECONDS {
            return Err("token too old".to_string());
        }
    }

    let scope_val = payload.get("scope").ok_or_else(|| "missing scope".to_string())?;
    if !has_scope(scope_val, &cfg.scope) {
        return Err("missing scope".to_string());
    }

    if let Some(ref host) = cfg.host {
        let host_val = payload.get("host").and_then(|v| v.as_str()).ok_or_else(|| "host mismatch".to_string())?;
        if host_val != host {
            return Err("host mismatch".to_string());
        }
    }

    Ok(())
}

fn jwt_check_internal(state: &State, cfg: &Config, command_info: *const *const c_char, run_argv: *const *const c_char, require_tty: bool) -> Result<(), String> {
    if !should_enforce_user(state, cfg) {
        return Ok(());
    }

    if !command_requires_jwt(cfg, command_info, run_argv) {
        return Ok(());
    }

    if require_tty && state.tty.as_deref().unwrap_or("").is_empty() {
        return Err("tty required".to_string());
    }

    let token = match read_token(&cfg.token_file) {
        Ok(t) => t,
        Err(e) => {
            if !cfg.require_jwt && e == "token missing" {
                return Ok(());
            }
            return Err(e);
        }
    };

    let payload = verify_jwt(cfg, &token)?;
    check_claims(cfg, &payload)?;
    Ok(())
}

extern "C" fn sudo_jwt_approval_open(
    version: c_uint,
    _conversation: SudoConvT,
    sudo_plugin_printf: SudoPrintfT,
    _settings: *const *const c_char,
    user_info: *const *const c_char,
    _submit_optind: c_int,
    _submit_argv: *const *const c_char,
    _submit_envp: *const *const c_char,
    plugin_options: *const *const c_char,
    errstr: *mut *const c_char,
) -> c_int {
    with_state(|state| {
        parse_debug_options(plugin_options);
        state.last_err = None;
        state.user = None;
        state.uid = None;
        state.tty = None;
        state.sudo_printf = sudo_plugin_printf;
        if (version >> 16) != SUDO_API_VERSION_MAJOR {
            set_err(state, errstr, "incompatible sudo plugin API");
            return -1;
        }

        let mut config_path = DEFAULT_CONFIG_PATH.to_string();
        unsafe {
            if !plugin_options.is_null() {
                let mut idx = 0;
                loop {
                    let ptr = *plugin_options.add(idx);
                    if ptr.is_null() { break; }
                    let s = CStr::from_ptr(ptr).to_string_lossy();
                    if let Some(val) = s.strip_prefix("config=") {
                        config_path = val.to_string();
                    }
                    idx += 1;
                }
            }
            if !user_info.is_null() {
                let mut idx = 0;
                while !(*user_info.add(idx)).is_null() {
                    let s = CStr::from_ptr(*user_info.add(idx)).to_string_lossy();
                    if let Some(val) = s.strip_prefix("user=") {
                        state.user = Some(val.to_string());
                    } else if let Some(val) = s.strip_prefix("uid=") {
                        state.uid = val.parse::<u32>().ok();
                    } else if let Some(val) = s.strip_prefix("tty=") {
                        state.tty = Some(val.to_string());
                    }
                    idx += 1;
                }
            }
        }

        match parse_config(&config_path, state.user.as_deref(), state.uid) {
            Ok(cfg) => {
                state.config = Some(cfg);
                1
            }
            Err(e) => {
                set_err(state, errstr, &e);
                -1
            }
        }
    })
}

extern "C" fn sudo_jwt_approval_close() {
    with_state(|state| {
        state.config = None;
        state.user = None;
        state.uid = None;
        state.tty = None;
        state.last_err = None;
        state.sudo_printf = None;
    });
}

extern "C" fn sudo_jwt_approval_check(
    command_info: *const *const c_char,
    run_argv: *const *const c_char,
    _run_envp: *const *const c_char,
    errstr: *mut *const c_char,
) -> c_int {
    with_state(|state| {
        let Some(ref cfg) = state.config else {
            set_err(state, errstr, "policy not initialized");
            return -1;
        };
        match jwt_check_internal(state, cfg, command_info, run_argv, cfg.require_tty) {
            Ok(()) => 1,
            Err(e) => {
                set_err(state, errstr, &e);
                log_error(state, "sudo-awesome-jwt-approval", &e);
                0
            }
        }
    })
}

extern "C" fn sudo_jwt_approval_show_version(_verbose: c_int) -> c_int {
    1
}

#[no_mangle]
#[used]
pub static approval: approval_plugin = approval_plugin {
    plugin_type: SUDO_APPROVAL_PLUGIN,
    version: SUDO_API_VERSION,
    open: Some(sudo_jwt_approval_open),
    close: Some(sudo_jwt_approval_close),
    check: Some(sudo_jwt_approval_check),
    show_version: Some(sudo_jwt_approval_show_version),
};

extern "C" fn sudo_jwt_policy_open(
    version: c_uint,
    _conversation: SudoConvT,
    sudo_plugin_printf: SudoPrintfT,
    _settings: *const *const c_char,
    user_info: *const *const c_char,
    _user_env: *const *const c_char,
    plugin_options: *const *const c_char,
    errstr: *mut *const c_char,
) -> c_int {
    debug_log("policy_open");
    sudo_jwt_approval_open(version, None, sudo_plugin_printf, ptr::null(), user_info, 0, ptr::null(), ptr::null(), plugin_options, errstr)
}

extern "C" fn sudo_jwt_policy_close(_exit_status: c_int, _error: c_int) {
    debug_log("policy_close");
    sudo_jwt_approval_close();
}

extern "C" fn sudo_jwt_policy_show_version(_verbose: c_int) -> c_int {
    debug_log("policy_show_version");
    1
}

extern "C" fn sudo_jwt_policy_check(
    _argc: c_int,
    argv: *const *const c_char,
    _env_add: *const *const c_char,
    command_info: *mut *const *const c_char,
    argv_out: *mut *const *const c_char,
    user_env_out: *mut *const *const c_char,
    errstr: *mut *const c_char,
) -> c_int {
    debug_log("policy_check");
    unsafe {
        if !command_info.is_null() {
            with_state(|state| {
                let (entries, ptrs) = build_command_info(argv);
                debug_dump_command_info(&entries);
                state.command_info = Some(entries);
                state.command_info_ptrs = Some(ptrs);
                if let Some(ref ptrs) = state.command_info_ptrs {
                    *command_info = ptrs.as_ptr() as *const *const c_char;
                }
            });
        }
        if !argv_out.is_null() {
            *argv_out = argv;
        }
        if !user_env_out.is_null() {
            with_state(|state| {
                state.env_ptrs = Some(vec![0]);
                if let Some(ref env) = state.env_ptrs {
                    *user_env_out = env.as_ptr() as *const *const c_char;
                }
            });
            debug_log("envp set to empty list");
        }
    }
    with_state(|state| {
        let Some(ref cfg) = state.config else {
            set_err(state, errstr, "policy not initialized");
            return -1;
        };
        match jwt_check_internal(state, cfg, ptr::null(), argv, cfg.require_tty) {
            Ok(()) => 1,
            Err(e) => {
                set_err(state, errstr, &e);
                log_error(state, "sudo-awesome-jwt-policy", &e);
                0
            }
        }
    })
}

extern "C" fn sudo_jwt_policy_list(
    _argc: c_int,
    _argv: *const *const c_char,
    _verbose: c_int,
    _user: *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    debug_log("policy_list");
    1
}

extern "C" fn sudo_jwt_policy_validate(_errstr: *mut *const c_char) -> c_int {
    debug_log("policy_validate");
    1
}

extern "C" fn sudo_jwt_policy_invalidate(_rmcred: c_int) {}

extern "C" fn sudo_jwt_policy_init_session(
    _pwd: *mut libc::passwd,
    _user_env_out: *mut *const *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    debug_log("policy_init_session");
    1
}

#[no_mangle]
#[used]
pub static policy: policy_plugin = policy_plugin {
    plugin_type: SUDO_POLICY_PLUGIN,
    version: SUDO_API_VERSION,
    open: Some(sudo_jwt_policy_open),
    close: Some(sudo_jwt_policy_close),
    show_version: Some(sudo_jwt_policy_show_version),
    check_policy: Some(sudo_jwt_policy_check),
    list: Some(sudo_jwt_policy_list),
    validate: Some(sudo_jwt_policy_validate),
    invalidate: Some(sudo_jwt_policy_invalidate),
    init_session: Some(sudo_jwt_policy_init_session),
    register_hooks: None,
    deregister_hooks: None,
    event_alloc: None,
};
