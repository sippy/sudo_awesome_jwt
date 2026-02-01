use crate::common::*;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

extern "C" fn sudo_jwt_policy_open(
    version: c_uint,
    _conversation: SudoConvT,
    sudo_plugin_printf: SudoPrintfT,
    settings: *const *const c_char,
    user_info: *const *const c_char,
    user_env: *const *const c_char,
    plugin_options: *const *const c_char,
    errstr: *mut *const c_char,
) -> c_int {
    parse_debug_options(plugin_options);
    sudo_jwt_open_internal(
        PREFIX_POLICY,
        "policy_open",
        debug_log_policy_state,
        version,
        sudo_plugin_printf,
        user_info,
        user_env,
        settings,
        plugin_options,
        errstr,
    )
}

extern "C" fn sudo_jwt_policy_close(_exit_status: c_int, _error: c_int) {
    sudo_jwt_close_internal("policy_close", debug_log_policy_state);
}

extern "C" fn sudo_jwt_policy_show_version(_verbose: c_int) -> c_int {
    debug_log_policy("policy_show_version");
    with_state(|state| log_version(state, "Policy"));
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
    debug_log_policy("policy_check");
    unsafe {
        let cmd = if !argv.is_null() && !(*argv).is_null() {
            CStr::from_ptr(*argv).to_string_lossy().into_owned()
        } else {
            String::new()
        };
        let resolved = with_state(|state| {
            resolve_command_path(&cmd, state.user_env.as_deref()).unwrap_or_else(|| cmd.clone())
        });
        if debug_enabled() && resolved != cmd {
            debug_log_policy(&format!("resolved command_path={resolved}"));
        }
        if !command_info.is_null() {
            with_state(|state| {
                let cmd_for_info = if resolved != cmd { &resolved } else { &cmd };
                let (entries, ptrs) = build_command_info_with_path(
                    cmd_for_info,
                    &resolved,
                    state.runas_user.as_deref(),
                    state.runas_uid,
                    state.runas_gid,
                    state.runas_group.as_deref(),
                );
                debug_dump_command_info(state, &entries);
                state.command_info = Some(entries);
                state.command_info_ptrs = Some(ptrs);
                if let Some(ref ptrs) = state.command_info_ptrs {
                    *command_info = ptrs.as_ptr() as *const *const c_char;
                }
            });
        }
        if !argv_out.is_null() {
            if resolved != cmd {
                with_state(|state| {
                    if let Some((argv_entries, argv_ptrs)) = build_argv_out(argv, &resolved) {
                        state.run_argv = Some(argv_entries);
                        state.run_argv_ptrs = Some(argv_ptrs);
                        if let Some(ref ptrs) = state.run_argv_ptrs {
                            *argv_out = ptrs.as_ptr() as *const *const c_char;
                            debug_dump_argv_out(state, *argv_out);
                            return;
                        }
                    }
                    if !argv.is_null() {
                        *argv_out = argv;
                        debug_dump_argv_out(state, *argv_out);
                    }
                });
            } else if !argv.is_null() {
                with_state(|state| {
                    *argv_out = argv;
                    debug_dump_argv_out(state, *argv_out);
                });
            }
        }
        if !user_env_out.is_null() {
            with_state(|state| {
                if state.user_env_ptrs.is_none() {
                    state.user_env_ptrs = Some(vec![0]);
                }
                if let Some(ref env) = state.user_env_ptrs {
                    *user_env_out = env.as_ptr() as *const *const c_char;
                }
            });
            debug_log_policy("envp set from policy open");
        }
    }
    with_state(|state| {
        let Some(ref cfg) = state.config else {
            set_err(state, errstr, "policy not initialized");
            debug_log_policy_state(state, "policy_check: policy not initialized");
            return -1;
        };
        let cmd_info_ptr = state
            .command_info_ptrs
            .as_ref()
            .map(|ptrs| ptrs.as_ptr() as *const *const c_char)
            .unwrap_or(ptr::null());
        let rc = match jwt_check_internal(state, cfg, cmd_info_ptr, argv, cfg.require_tty, true) {
            Ok(()) => 1,
            Err(e) => {
                set_err(state, errstr, &e);
                log_error(state, PREFIX_POLICY, &e);
                debug_log_policy_state(state, &format!("policy_check: {e}"));
                0
            }
        };
        debug_log_policy_state(state, &format!("policy_check rc={rc}"));
        rc
    })
}

extern "C" fn sudo_jwt_policy_list(
    _argc: c_int,
    _argv: *const *const c_char,
    _verbose: c_int,
    _user: *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    debug_log_policy("policy_list");
    with_state(|state| log_version(state, "Policy"));
    1
}

extern "C" fn sudo_jwt_policy_validate(_errstr: *mut *const c_char) -> c_int {
    debug_log_policy("policy_validate");
    1
}

extern "C" fn sudo_jwt_policy_invalidate(_rmcred: c_int) {
    debug_log_policy("policy_invalidate");
}

extern "C" fn sudo_jwt_policy_init_session(
    _pwd: *mut libc::passwd,
    _user_env_out: *mut *const *const c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    debug_log_policy("policy_init_session");
    1
}

#[no_mangle]
#[used]
#[link_section = ".data"]
pub static mut policy: policy_plugin = policy_plugin {
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
