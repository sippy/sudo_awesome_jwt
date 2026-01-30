use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::fs;
use std::collections::HashMap;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let manifest_path = PathBuf::from(&manifest_dir);
    let map_path = manifest_path.join("../src/exports.map");
    if map_path.exists() {
        println!("cargo:rustc-link-arg=-Wl,--version-script={}", map_path.display());
    }

    let macros = detect_macros().unwrap_or_default();
    let major = parse_u32(macros.get("SUDO_API_VERSION_MAJOR")).unwrap_or(1);
    let minor = parse_u32(macros.get("SUDO_API_VERSION_MINOR")).unwrap_or(22);
    let version = ((major as u32) << 16) | (minor as u32);
    let conv_error = parse_u32(macros.get("SUDO_CONV_ERROR_MSG")).unwrap_or(0x0003);
    let conv_info = parse_u32(macros.get("SUDO_CONV_INFO_MSG")).unwrap_or(0x0004);
    let policy_plugin = parse_u32(macros.get("SUDO_POLICY_PLUGIN")).unwrap_or(1);
    let approval_plugin = parse_u32(macros.get("SUDO_APPROVAL_PLUGIN")).unwrap_or(4);
    let default_config = parse_str(macros.get("DEFAULT_CONFIG_PATH"))
        .unwrap_or_else(|| "/usr/local/etc/sudo_awesome_jwt.conf".to_string());
    let default_scope = parse_str(macros.get("DEFAULT_SCOPE"))
        .unwrap_or_else(|| "sudo".to_string());
    let max_token = parse_u64(macros.get("MAX_TOKEN_BYTES")).unwrap_or(16 * 1024);
    let max_aud = parse_u64(macros.get("MAX_AUDIENCE_BYTES")).unwrap_or(1024);
    let max_allow = parse_u64(macros.get("MAX_ALLOWLIST_BYTES")).unwrap_or(4096);
    let clock_skew = parse_i64(macros.get("CLOCK_SKEW_SECONDS")).unwrap_or(60);
    let plugin_version = parse_str(macros.get("SUDO_AWESOME_JWT_VERSION"))
        .unwrap_or_else(|| "0.1.0".to_string());
    let plugin_name = parse_str(macros.get("SUDO_AWESOME_JWT_NAME"))
        .unwrap_or_else(|| "sudo-awesome-jwt".to_string());
    let runas_user_default = parse_str(macros.get("SUDO_AWESOME_JWT_RUNAS_USER_DEFAULT"))
        .unwrap_or_else(|| "root".to_string());
    let runas_uid_default = parse_u32(macros.get("SUDO_AWESOME_JWT_RUNAS_UID_DEFAULT")).unwrap_or(0);
    let runas_gid_default = parse_u32(macros.get("SUDO_AWESOME_JWT_RUNAS_GID_DEFAULT")).unwrap_or(0);
    let prefix_policy = parse_str(macros.get("SUDO_AWESOME_JWT_POLICY"))
        .unwrap_or_else(|| "sudo-awesome-jwt:policy".to_string());
    let prefix_approval = parse_str(macros.get("SUDO_AWESOME_JWT_APPROVAL"))
        .unwrap_or_else(|| "sudo-awesome-jwt:approval".to_string());
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let out_path = PathBuf::from(out_dir).join("sudo_constants.rs");
    let contents = format!(
        "pub const SUDO_API_VERSION_MAJOR: u32 = {major};\n\
pub const SUDO_API_VERSION_MINOR: u32 = {minor};\n\
pub const SUDO_API_VERSION: u32 = {version};\n\
pub const SUDO_CONV_ERROR_MSG: i32 = {conv_error};\n\
pub const SUDO_CONV_INFO_MSG: i32 = {conv_info};\n\
pub const SUDO_POLICY_PLUGIN: u32 = {policy_plugin};\n\
pub const SUDO_APPROVAL_PLUGIN: u32 = {approval_plugin};\n\
pub const DEFAULT_CONFIG_PATH: &str = \"{default_config}\";\n\
pub const DEFAULT_SCOPE: &str = \"{default_scope}\";\n\
pub const MAX_TOKEN_BYTES: u64 = {max_token};\n\
pub const MAX_AUDIENCE_BYTES: u64 = {max_aud};\n\
pub const MAX_ALLOWLIST_BYTES: u64 = {max_allow};\n\
pub const CLOCK_SKEW_SECONDS: i64 = {clock_skew};\n\
pub const SUDO_AWESOME_JWT_VERSION: &str = \"{plugin_version}\";\n\
pub const SUDO_AWESOME_JWT_NAME: &str = \"{plugin_name}\";\n\
pub const SUDO_AWESOME_JWT_RUNAS_USER_DEFAULT: &str = \"{runas_user_default}\";\n\
pub const SUDO_AWESOME_JWT_RUNAS_UID_DEFAULT: u32 = {runas_uid_default};\n\
pub const SUDO_AWESOME_JWT_RUNAS_GID_DEFAULT: u32 = {runas_gid_default};\n\
pub const PREFIX_POLICY: &str = \"{prefix_policy}\";\n\
pub const PREFIX_APPROVAL: &str = \"{prefix_approval}\";\n"
    );
    fs::write(out_path, contents).expect("write sudo_constants.rs");

    println!("cargo:rerun-if-changed=/usr/include/sudo_plugin.h");
    println!("cargo:rerun-if-changed=/usr/local/include/sudo_plugin.h");
    println!(
        "cargo:rerun-if-changed={}",
        manifest_path.join("../src/sudo_jwt_common.h").display()
    );

    println!("cargo:rerun-if-env-changed=OPENSSL_STATIC");
    if env::var("OPENSSL_STATIC").ok().as_deref() == Some("1") {
        println!("cargo:warning=OPENSSL_STATIC=1 requested; linking libcrypto/libssl statically");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=ssl");
    }
}

fn detect_macros() -> Option<HashMap<String, String>> {
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").ok()?;
    let common_header = PathBuf::from(manifest_dir).join("../src/sudo_jwt_common.h");
    let output = Command::new(cc)
        .args([
            "-dM",
            "-E",
            "-I",
            "/usr/local/include",
            "-I",
            "/usr/include",
            "-include",
            common_header.to_str()?,
            "-",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut out = HashMap::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("#define ") {
            let mut parts = rest.splitn(2, ' ');
            let name = parts.next()?.trim();
            let value = parts.next().unwrap_or("").trim();
            out.insert(name.to_string(), value.to_string());
        }
    }
    Some(out)
}

fn parse_u32(val: Option<&String>) -> Option<u32> {
    val.and_then(|v| parse_u32_str(v))
}

fn parse_u64(val: Option<&String>) -> Option<u64> {
    val.and_then(|v| parse_u64_str(v))
}

fn parse_i64(val: Option<&String>) -> Option<i64> {
    val.and_then(|v| parse_i64_str(v))
}

fn parse_u32_str(s: &str) -> Option<u32> {
    parse_u64_str(s).and_then(|val| u32::try_from(val).ok())
}

fn parse_u64_str(s: &str) -> Option<u64> {
    let s = normalize_numeric(s);
    if s.starts_with('-') {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn parse_i64_str(s: &str) -> Option<i64> {
    let s = normalize_numeric(s);
    if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        i64::from_str_radix(hex, 16).ok().map(|val| -val)
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<i64>().ok()
    }
}

fn normalize_numeric(mut s: &str) -> &str {
    s = s.trim();
    while s.starts_with('(') && s.ends_with(')') && s.len() >= 2 {
        s = s[1..s.len() - 1].trim();
    }
    s.trim_end_matches(|c| matches!(c, 'u' | 'U' | 'l' | 'L'))
}

fn parse_str(val: Option<&String>) -> Option<String> {
    let raw = val?.trim();
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        let inner = &raw[1..raw.len() - 1];
        let unescaped = inner
            .replace("\\\\", "\\")
            .replace("\\\"", "\"")
            .replace("\\n", "\n")
            .replace("\\t", "\t");
        Some(unescaped)
    } else if raw.is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}
