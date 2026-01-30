use crate::common::*;
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;

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
    parse_debug_options(plugin_options);
    sudo_jwt_open_internal(
        PREFIX_APPROVAL,
        "approval_open",
        debug_log_approval_state,
        version,
        sudo_plugin_printf,
        user_info,
        ptr::null(),
        ptr::null(),
        plugin_options,
        errstr,
    )
}

extern "C" fn sudo_jwt_approval_close() {
    sudo_jwt_close_internal("approval_close", debug_log_approval_state);
}

extern "C" fn sudo_jwt_approval_check(
    command_info: *const *const c_char,
    run_argv: *const *const c_char,
    _run_envp: *const *const c_char,
    errstr: *mut *const c_char,
) -> c_int {
    debug_log_approval("approval_check");
    with_state(|state| {
        let Some(ref cfg) = state.config else {
            set_err(state, errstr, "policy not initialized");
            debug_log_approval_state(state, "approval_check: policy not initialized");
            return -1;
        };
        let rc = match jwt_check_internal(state, cfg, command_info, run_argv, cfg.require_tty) {
            Ok(()) => 1,
            Err(e) => {
                set_err(state, errstr, &e);
                log_error(state, PREFIX_APPROVAL, &e);
                debug_log_approval_state(state, &format!("approval_check: {e}"));
                0
            }
        };
        debug_log_approval_state(state, &format!("approval_check rc={rc}"));
        rc
    })
}

extern "C" fn sudo_jwt_approval_show_version(_verbose: c_int) -> c_int {
    debug_log_approval("approval_show_version");
    with_state(|state| log_version(state, "Approval"));
    1
}

#[no_mangle]
#[used]
#[link_section = ".data"]
pub static mut approval: approval_plugin = approval_plugin {
    plugin_type: SUDO_APPROVAL_PLUGIN,
    version: SUDO_API_VERSION,
    open: Some(sudo_jwt_approval_open),
    close: Some(sudo_jwt_approval_close),
    check: Some(sudo_jwt_approval_check),
    show_version: Some(sudo_jwt_approval_show_version),
};
