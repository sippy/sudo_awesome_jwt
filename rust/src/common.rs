use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::hash::MessageDigest;
use serde_json::Value;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/sudo_constants.rs"));

const SUDO_API_VERSION_MINOR_MASK: u32 = 0xFFFF;

fn sudo_api_version_get_major(version: c_uint) -> u32 {
    version >> 16
}

fn sudo_api_version_get_minor(version: c_uint) -> u32 {
    (version & SUDO_API_VERSION_MINOR_MASK) as u32
}

#[repr(C)]
pub struct approval_plugin {
    pub(crate) plugin_type: c_uint,
    pub(crate) version: c_uint,
    pub(crate) open: Option<extern "C" fn(c_uint, SudoConvT, SudoPrintfT, *const *const c_char, *const *const c_char, c_int, *const *const c_char, *const *const c_char, *const *const c_char, *mut *const c_char) -> c_int>,
    pub(crate) close: Option<extern "C" fn()>,
    pub(crate) check: Option<extern "C" fn(*const *const c_char, *const *const c_char, *const *const c_char, *mut *const c_char) -> c_int>,
    pub(crate) show_version: Option<extern "C" fn(c_int) -> c_int>,
}

#[repr(C)]
pub struct policy_plugin {
    pub(crate) plugin_type: c_uint,
    pub(crate) version: c_uint,
    pub(crate) open: Option<extern "C" fn(c_uint, SudoConvT, SudoPrintfT, *const *const c_char, *const *const c_char, *const *const c_char, *const *const c_char, *mut *const c_char) -> c_int>,
    pub(crate) close: Option<extern "C" fn(c_int, c_int)>,
    pub(crate) show_version: Option<extern "C" fn(c_int) -> c_int>,
    pub(crate) check_policy: Option<extern "C" fn(c_int, *const *const c_char, *const *const c_char, *mut *const *const c_char, *mut *const *const c_char, *mut *const *const c_char, *mut *const c_char) -> c_int>,
    pub(crate) list: Option<extern "C" fn(c_int, *const *const c_char, c_int, *const c_char, *mut *const c_char) -> c_int>,
    pub(crate) validate: Option<extern "C" fn(*mut *const c_char) -> c_int>,
    pub(crate) invalidate: Option<extern "C" fn(c_int)>,
    pub(crate) init_session: Option<extern "C" fn(*mut libc::passwd, *mut *const *const c_char, *mut *const c_char) -> c_int>,
    pub(crate) register_hooks: Option<extern "C" fn(c_int, *mut libc::c_void)>,
    pub(crate) deregister_hooks: Option<extern "C" fn(c_int, *mut libc::c_void)>,
    pub(crate) event_alloc: Option<extern "C" fn() -> *mut libc::c_void>,
}

pub(crate) type SudoConvT = Option<extern "C" fn(c_int, *const libc::c_void, *mut libc::c_void, *mut libc::c_void) -> c_int>;
pub(crate) type SudoPrintfT = Option<extern "C" fn(c_int, *const c_char, ...) -> c_int>;

#[derive(Default)]
pub(crate) struct State {
    pub(crate) config: Option<Config>,
    pub(crate) user: Option<String>,
    pub(crate) uid: Option<u32>,
    pub(crate) tty: Option<String>,
    pub(crate) last_err: Option<CString>,
    pub(crate) command_info: Option<Vec<CString>>,
    pub(crate) command_info_ptrs: Option<Vec<usize>>,
    pub(crate) user_env: Option<Vec<CString>>,
    pub(crate) user_env_ptrs: Option<Vec<usize>>,
    pub(crate) run_argv: Option<Vec<CString>>,
    pub(crate) run_argv_ptrs: Option<Vec<usize>>,
    pub(crate) runas_user: Option<String>,
    pub(crate) runas_uid: Option<u32>,
    pub(crate) runas_gid: Option<u32>,
    pub(crate) runas_group: Option<String>,
    pub(crate) setenv_requested: bool,
    pub(crate) sudo_printf: SudoPrintfT,
}

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) token_file: String,
    pub(crate) public_key: String,
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) scope: String,
    pub(crate) host: Option<String>,
    pub(crate) max_ttl: i64,
    pub(crate) require_jwt: bool,
    pub(crate) require_tty: bool,
    pub(crate) only_user: Option<String>,
    pub(crate) only_uid: Option<u32>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static DEBUG_OVERRIDE: AtomicBool = AtomicBool::new(false);

pub(crate) fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    let mutex = STATE.get_or_init(|| Mutex::new(State::default()));
    let mut state = mutex.lock().expect("state lock");
    f(&mut state)
}

pub(crate) fn set_err(state: &mut State, errstr: *mut *const c_char, msg: &str) {
    state.last_err = CString::new(msg).ok();
    if let Some(ref cstr) = state.last_err {
        unsafe {
            if !errstr.is_null() {
                *errstr = cstr.as_ptr();
            }
        }
    }
}

pub(crate) fn log_error(state: &State, prefix: &str, msg: &str) {
    let Some(printf_fn) = state.sudo_printf else { return; };
    let message = format!("{prefix}:{msg}\n");
    let fmt = CString::new("%s").ok();
    let msg_c = CString::new(message).ok();
    if let (Some(fmt), Some(msg_c)) = (fmt, msg_c) {
        printf_fn(SUDO_CONV_ERROR_MSG, fmt.as_ptr(), msg_c.as_ptr());
    }
}

fn log_debug(state: &State, prefix: &str, msg: &str) {
    let Some(printf_fn) = state.sudo_printf else { return; };
    let message = format!("{prefix}:{msg}\n");
    let fmt = CString::new("%s").ok();
    let msg_c = CString::new(message).ok();
    if let (Some(fmt), Some(msg_c)) = (fmt, msg_c) {
        printf_fn(SUDO_CONV_ERROR_MSG, fmt.as_ptr(), msg_c.as_ptr());
    }
}

pub(crate) fn log_version(state: &State, label: &str) {
    let Some(printf_fn) = state.sudo_printf else { return; };
    let kind = if label.is_empty() { "Plugin" } else { label };
    let line = format!(
        "{SUDO_AWESOME_JWT_NAME}: {kind} (Rust) version {SUDO_AWESOME_JWT_VERSION}\n"
    );
    if let (Ok(fmt), Ok(msg)) = (CString::new("%s"), CString::new(line)) {
        printf_fn(SUDO_CONV_INFO_MSG, fmt.as_ptr(), msg.as_ptr());
    }
}

pub(crate) fn debug_enabled() -> bool {
    if DEBUG_OVERRIDE.load(Ordering::Relaxed) {
        return true;
    }
    match env::var("SUDO_AWESOME_JWT_DEBUG") {
        Ok(val) => !val.is_empty() && val != "0",
        Err(_) => false,
    }
}

pub(crate) fn debug_log_policy_state(state: &State, msg: &str) {
    if debug_enabled() {
        log_debug(state, PREFIX_POLICY, msg);
    }
}

pub(crate) fn debug_log_approval_state(state: &State, msg: &str) {
    if debug_enabled() {
        log_debug(state, PREFIX_APPROVAL, msg);
    }
}

pub(crate) fn debug_log_policy(msg: &str) {
    if debug_enabled() {
        with_state(|state| log_debug(state, PREFIX_POLICY, msg));
    }
}

pub(crate) fn debug_log_approval(msg: &str) {
    if debug_enabled() {
        with_state(|state| log_debug(state, PREFIX_APPROVAL, msg));
    }
}

    pub(crate) fn sudo_jwt_open_internal(
    prefix: &str,
    open_label: &str,
    log_fn: fn(&State, &str),
    version: c_uint,
    sudo_plugin_printf: SudoPrintfT,
    user_info: *const *const c_char,
    user_env: *const *const c_char,
    settings: *const *const c_char,
    plugin_options: *const *const c_char,
    errstr: *mut *const c_char,
) -> c_int {
    with_state(|state| {
        log_fn(state, open_label);
        state.last_err = None;
        state.user = None;
        state.uid = None;
        state.tty = None;
        state.sudo_printf = sudo_plugin_printf;
        state.user_env = None;
        state.user_env_ptrs = None;
        state.runas_user = None;
        state.runas_uid = None;
        state.runas_gid = None;
        state.runas_group = None;
        state.setenv_requested = false;
        debug_dump_plugin_options(state, plugin_options, prefix);
        let major = sudo_api_version_get_major(version);
        let minor = sudo_api_version_get_minor(version);
        if major != SUDO_API_VERSION_MAJOR {
            set_err(state, errstr, "incompatible sudo plugin API");
            return -1;
        }
        if minor != SUDO_API_VERSION_MINOR {
            log_debug(
                state,
                prefix,
                &format!(
                    "warning: sudo API minor mismatch (expected {}, got {})",
                    SUDO_API_VERSION_MINOR, minor
                ),
            );
        }

        let mut config_path = DEFAULT_CONFIG_PATH.to_string();
        unsafe {
            if !plugin_options.is_null() {
                let mut idx = 0;
                loop {
                    let ptr = *plugin_options.add(idx);
                    if ptr.is_null() {
                        break;
                    }
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
            if !settings.is_null() {
                let mut idx = 0;
                loop {
                    let ptr = *settings.add(idx);
                    if ptr.is_null() {
                        break;
                    }
                    let s = CStr::from_ptr(ptr).to_string_lossy();
                    if let Some(val) = s.strip_prefix("runas_user=") {
                        if !val.is_empty() {
                            state.runas_user = Some(val.to_string());
                        }
                    } else if let Some(val) = s.strip_prefix("runas_group=") {
                        if !val.is_empty() {
                            state.runas_group = Some(val.to_string());
                        }
                    } else if let Some(val) = s.strip_prefix("runas_uid=") {
                        if let Ok(parsed) = val.parse::<u32>() {
                            state.runas_uid = Some(parsed);
                        }
                    } else if let Some(val) = s.strip_prefix("runas_gid=") {
                        if let Ok(parsed) = val.parse::<u32>() {
                            state.runas_gid = Some(parsed);
                        }
                    }
                    idx += 1;
                }
            }
        }

        if state.runas_user.is_some()
            && (state.runas_uid.is_none() || state.runas_gid.is_none())
        {
            if let Some(ref user) = state.runas_user {
                if let Ok(c_user) = CString::new(user.as_str()) {
                    unsafe {
                        let pw = libc::getpwnam(c_user.as_ptr());
                        if !pw.is_null() {
                            let pw_ref = &*pw;
                            if state.runas_uid.is_none() {
                                state.runas_uid = Some(pw_ref.pw_uid);
                            }
                            if state.runas_gid.is_none() {
                                state.runas_gid = Some(pw_ref.pw_gid);
                            }
                        }
                    }
                }
            }
        }

        if let Some((entries, ptrs)) = build_user_env(user_env).or_else(build_fallback_env) {
            debug_dump_user_env(state, &entries);
            state.user_env = Some(entries);
            state.user_env_ptrs = Some(ptrs);
        }

        match parse_config(&config_path, state.user.as_deref(), state.uid) {
            Ok(cfg) => {
                state.config = Some(cfg);
                log_fn(state, &format!("{open_label}: using config {config_path}"));
                log_fn(state, &format!("{open_label}: config loaded"));
                1
            }
            Err(e) => {
                set_err(state, errstr, &e);
                log_fn(state, &format!("{open_label}: {e}"));
                -1
            }
        }
    })
}

pub(crate) fn sudo_jwt_close_internal(close_label: &str, log_fn: fn(&State, &str)) {
    with_state(|state| {
        log_fn(state, close_label);
        state.config = None;
        state.user = None;
        state.uid = None;
        state.tty = None;
        state.last_err = None;
        state.user_env = None;
        state.user_env_ptrs = None;
        state.run_argv = None;
        state.run_argv_ptrs = None;
        state.runas_user = None;
        state.runas_uid = None;
        state.runas_gid = None;
        state.runas_group = None;
        state.setenv_requested = false;
        state.sudo_printf = None;
    });
}

fn debug_dump_plugin_options(state: &State, plugin_options: *const *const c_char, prefix: &str) {
    if !debug_enabled() {
        return;
    }
    unsafe {
        log_debug(state, prefix, "plugin options:");
        if plugin_options.is_null() {
            log_debug(state, prefix, "  (none)");
            return;
        }
        let mut idx = 0;
        loop {
            let ptr = *plugin_options.add(idx);
            if ptr.is_null() {
                break;
            }
            let s = CStr::from_ptr(ptr).to_string_lossy();
            log_debug(state, prefix, &format!("  {s}"));
            idx += 1;
        }
    }
}

pub(crate) fn parse_debug_options(plugin_options: *const *const c_char) {
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
                let val = val.trim();
                if val == "1" || val.eq_ignore_ascii_case("true") || val.eq_ignore_ascii_case("yes") {
                    DEBUG_OVERRIDE.store(true, Ordering::Relaxed);
                } else if val == "0" || val.eq_ignore_ascii_case("false") || val.eq_ignore_ascii_case("no") {
                    DEBUG_OVERRIDE.store(false, Ordering::Relaxed);
                }
            }
            idx += 1;
        }
    }
}

pub(crate) fn debug_dump_command_info(state: &State, entries: &[CString]) {
    if !debug_enabled() {
        return;
    }
    log_debug(state, PREFIX_POLICY, "command_info dump:");
    for entry in entries {
        log_debug(state, PREFIX_POLICY, &format!("  {}", entry.to_string_lossy()));
    }
}

fn debug_dump_user_env(state: &State, entries: &[CString]) {
    if !debug_enabled() {
        return;
    }
    log_debug(state, PREFIX_POLICY, "user_env dump:");
    for entry in entries {
        log_debug(state, PREFIX_POLICY, &format!("  {}", entry.to_string_lossy()));
    }
}

pub(crate) fn build_command_info_with_path(
    cmd: &str,
    cmd_path: &str,
    runas_user: Option<&str>,
    runas_uid: Option<u32>,
    runas_gid: Option<u32>,
    runas_group: Option<&str>,
) -> (Vec<CString>, Vec<usize>) {
    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("/"))
        .to_string_lossy()
        .into_owned();
    let mut entries = Vec::new();
    entries.push(CString::new(format!("command={cmd}")).unwrap());
    entries.push(CString::new(format!("command_path={cmd_path}")).unwrap());
    let runas_user = runas_user.unwrap_or(SUDO_AWESOME_JWT_RUNAS_USER_DEFAULT);
    let runas_uid = runas_uid.unwrap_or(SUDO_AWESOME_JWT_RUNAS_UID_DEFAULT);
    let runas_gid = runas_gid.unwrap_or(SUDO_AWESOME_JWT_RUNAS_GID_DEFAULT);
    entries.push(CString::new(format!("runas_user={runas_user}")).unwrap());
    entries.push(CString::new(format!("runas_uid={runas_uid}")).unwrap());
    entries.push(CString::new(format!("runas_gid={runas_gid}")).unwrap());
    if let Some(group) = runas_group {
        if !group.is_empty() {
            entries.push(CString::new(format!("runas_group={group}")).unwrap());
        }
    }
    entries.push(CString::new(format!("cwd={cwd}")).unwrap());
    let mut ptrs: Vec<usize> = entries.iter().map(|c| c.as_ptr() as usize).collect();
    ptrs.push(0);
    (entries, ptrs)
}

pub(crate) fn debug_dump_argv_out(state: &State, argv: *const *const c_char) {
    if !debug_enabled() {
        return;
    }
    unsafe {
        if argv.is_null() {
            log_debug(state, PREFIX_POLICY, "argv_out dump: (null)");
            return;
        }
        log_debug(state, PREFIX_POLICY, "argv_out dump:");
        let mut idx = 0;
        loop {
            let ptr = *argv.add(idx);
            if ptr.is_null() {
                break;
            }
            let s = CStr::from_ptr(ptr).to_string_lossy();
            log_debug(state, PREFIX_POLICY, &format!("  [{idx}] {s}"));
            idx += 1;
        }
    }
}

fn resolve_path_env(user_env: Option<&[CString]>) -> Option<String> {
    if let Some(env) = user_env {
        for entry in env {
            if let Ok(s) = entry.to_str() {
                if let Some(rest) = s.strip_prefix("PATH=") {
                    if !rest.is_empty() {
                        return Some(rest.to_string());
                    }
                }
            }
        }
    }
    std::env::var("PATH").ok().filter(|v| !v.is_empty())
}

pub(crate) fn resolve_command_path(cmd: &str, user_env: Option<&[CString]>) -> Option<String> {
    if cmd.is_empty() {
        return None;
    }
    if cmd.contains('/') {
        return Some(cmd.to_string());
    }
    let path = resolve_path_env(user_env)?;
    for dir in path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(dir).join(cmd);
        let bytes = candidate.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.contains(&0) {
            continue;
        }
        if let Ok(cstr) = CString::new(bytes) {
            let rc = unsafe { libc::access(cstr.as_ptr(), libc::X_OK) };
            if rc == 0 {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

pub(crate) fn build_argv_out(argv: *const *const c_char, resolved: &str) -> Option<(Vec<CString>, Vec<usize>)> {
    let mut entries = Vec::new();
    entries.push(CString::new(resolved).ok()?);
    unsafe {
        if !argv.is_null() {
            let mut idx = 1;
            loop {
                let ptr = *argv.add(idx);
                if ptr.is_null() {
                    break;
                }
                let raw = CStr::from_ptr(ptr).to_bytes();
                let cstr = CString::new(raw).ok()?;
                entries.push(cstr);
                idx += 1;
            }
        }
    }
    let mut ptrs: Vec<usize> = entries.iter().map(|c| c.as_ptr() as usize).collect();
    ptrs.push(0);
    Some((entries, ptrs))
}

pub(crate) fn build_user_env(user_env: *const *const c_char) -> Option<(Vec<CString>, Vec<usize>)> {
    if user_env.is_null() {
        return None;
    }
    let mut entries = Vec::new();
    unsafe {
        let mut idx = 0;
        loop {
            let ptr = *user_env.add(idx);
            if ptr.is_null() {
                break;
            }
            let raw = CStr::from_ptr(ptr).to_bytes();
            if let Ok(cstr) = CString::new(raw) {
                entries.push(cstr);
            }
            idx += 1;
        }
    }
    if entries.is_empty() {
        return None;
    }
    let mut ptrs: Vec<usize> = entries.iter().map(|c| c.as_ptr() as usize).collect();
    ptrs.push(0);
    Some((entries, ptrs))
}

fn build_fallback_env() -> Option<(Vec<CString>, Vec<usize>)> {
    let path = std::env::var("PATH").ok()?;
    let entry = CString::new(format!("PATH={path}")).ok()?;
    let entries = vec![entry];
    let mut ptrs: Vec<usize> = entries.iter().map(|c| c.as_ptr() as usize).collect();
    ptrs.push(0);
    Some((entries, ptrs))
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
            let mut command = None;
            let mut command_path = None;
            loop {
                let ptr = *command_info.add(idx);
                if ptr.is_null() { break; }
                let s = CStr::from_ptr(ptr).to_string_lossy();
                if let Some(val) = s.strip_prefix("command_path=") {
                    command_path = Some(val.to_string());
                } else if let Some(val) = s.strip_prefix("command=") {
                    command = Some(val.to_string());
                }
                idx += 1;
            }
            if command_path.is_some() {
                return command_path;
            }
            if command.is_some() {
                return command;
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

fn runas_from_info(command_info: *const *const c_char) -> (Option<String>, Option<u32>, Option<u32>, Option<String>) {
    let mut runas_user = None;
    let mut runas_uid = None;
    let mut runas_gid = None;
    let mut runas_group = None;
    unsafe {
        if !command_info.is_null() {
            let mut idx = 0;
            loop {
                let ptr = *command_info.add(idx);
                if ptr.is_null() { break; }
                let s = CStr::from_ptr(ptr).to_string_lossy();
                if let Some(val) = s.strip_prefix("runas_user=") {
                    if !val.is_empty() {
                        runas_user = Some(val.to_string());
                    }
                } else if let Some(val) = s.strip_prefix("runas_group=") {
                    if !val.is_empty() {
                        runas_group = Some(val.to_string());
                    }
                } else if let Some(val) = s.strip_prefix("runas_uid=") {
                    if let Ok(parsed) = val.parse::<u32>() {
                        runas_uid = Some(parsed);
                    }
                } else if let Some(val) = s.strip_prefix("runas_gid=") {
                    if let Ok(parsed) = val.parse::<u32>() {
                        runas_gid = Some(parsed);
                    }
                }
                idx += 1;
            }
        }
    }
    (runas_user, runas_uid, runas_gid, runas_group)
}

fn parse_setenv(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_i64().map(|v| v != 0),
        Value::String(s) => parse_bool(&s.to_ascii_lowercase()),
        _ => None,
    }
}

fn resolve_command_for_match(state: &State, command_info: *const *const c_char, run_argv: *const *const c_char) -> Result<String, String> {
    let mut cmd = command_from_info(command_info, run_argv).ok_or_else(|| "missing command".to_string())?;
    if !cmd.contains('/') {
        if let Some(resolved) = resolve_command_path(&cmd, state.user_env.as_deref()) {
            cmd = resolved;
        }
    }
    if let Ok(canon) = std::fs::canonicalize(&cmd) {
        cmd = canon.to_string_lossy().to_string();
    }
    Ok(cmd)
}

fn command_allowed_by_jwt(state: &State, payload: &Value, command_info: *const *const c_char, run_argv: *const *const c_char, policy_mode: bool) -> Result<(), String> {
    let cmd = resolve_command_for_match(state, command_info, run_argv)?;
    if debug_enabled() {
        log_debug(state, SUDO_AWESOME_JWT_NAME, &format!("resolved command={cmd}"));
    }
    let cmds = payload.get("cmds").ok_or_else(|| "missing cmds".to_string())?;
    let cmds = cmds.as_array().ok_or_else(|| "invalid cmds".to_string())?;
    let (runas_user, runas_uid, runas_gid, runas_group) = runas_from_info(command_info);
    if policy_mode {
        if cmds.iter().any(|entry| entry.get("setenv").is_some()) {
            return Err("setenv not supported in policy".to_string());
        }
    }
    let actual_setenv = if policy_mode { false } else { state.setenv_requested };

    let mut best_score: i32 = -1;
    for entry in cmds {
        let Some(obj) = entry.as_object() else { continue; };
        let Some(path) = obj.get("path").and_then(|v| v.as_str()) else { continue; };
        if path != cmd {
            continue;
        }
        let mut entry_score: i32 = 0;
        if let Some(req_user) = obj.get("runas_user").and_then(|v| v.as_str()) {
            if let Some(actual) = runas_user.as_deref() {
                if actual != req_user {
                    continue;
                }
                entry_score += 1;
            }
        }
        if let Some(req_uid) = obj.get("runas_uid").and_then(|v| v.as_u64()) {
            if let Some(actual_uid) = runas_uid {
                if actual_uid != req_uid as u32 {
                    continue;
                }
                entry_score += 1;
            }
        }
        if let Some(req_gid) = obj.get("runas_gid").and_then(|v| v.as_u64()) {
            if let Some(actual_gid) = runas_gid {
                if actual_gid != req_gid as u32 {
                    continue;
                }
                entry_score += 1;
            }
        }
        if let Some(req_group) = obj.get("runas_group").and_then(|v| v.as_str()) {
            if runas_group.as_deref() != Some(req_group) {
                continue;
            }
            entry_score += 1;
        }
        let expected_setenv = if let Some(val) = obj.get("setenv") {
            parse_setenv(val).ok_or_else(|| "invalid setenv".to_string())?
        } else {
            false
        };
        if obj.get("setenv").is_some() {
            if expected_setenv != actual_setenv {
                continue;
            }
            entry_score += 1;
        } else if actual_setenv {
            continue;
        }
        if entry_score > best_score {
            best_score = entry_score;
        }
    }

    if best_score >= 0 {
        Ok(())
    } else {
        Err("command not permitted".to_string())
    }
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

fn check_claims(cfg: &Config, payload: &Value, expected_user: &str) -> Result<(), String> {
    let iss = payload.get("iss").and_then(|v| v.as_str()).ok_or_else(|| "missing iss".to_string())?;
    if iss != cfg.issuer {
        return Err("issuer mismatch".to_string());
    }

    let aud = payload.get("aud").ok_or_else(|| "missing aud".to_string())?;
    if !aud_matches(aud, &cfg.audience) {
        return Err("audience mismatch".to_string());
    }

    let sub = payload.get("sub").and_then(|v| v.as_str()).ok_or_else(|| "missing sub".to_string())?;
    if sub != expected_user {
        return Err("sub mismatch".to_string());
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

pub(crate) fn jwt_check_internal(state: &State, cfg: &Config, command_info: *const *const c_char, run_argv: *const *const c_char, require_tty: bool, policy_mode: bool) -> Result<(), String> {
    if !should_enforce_user(state, cfg) {
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
    let user = state.user.as_deref().ok_or_else(|| "missing user".to_string())?;
    if let Err(e) = check_claims(cfg, &payload, user) {
        if debug_enabled() {
            log_debug(state, SUDO_AWESOME_JWT_NAME, &format!("jwt payload={payload}"));
        }
        return Err(e);
    }
    if let Err(e) = command_allowed_by_jwt(state, &payload, command_info, run_argv, policy_mode) {
        if debug_enabled() {
            log_debug(state, SUDO_AWESOME_JWT_NAME, &format!("jwt payload={payload}"));
        }
        return Err(e);
    }
    Ok(())
}
