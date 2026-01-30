use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::fs;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let map_path = PathBuf::from(manifest_dir).join("../src/exports.map");
    if map_path.exists() {
        println!("cargo:rustc-link-arg=-Wl,--version-script={}", map_path.display());
    }

    let (major, minor) = detect_sudo_api_version().unwrap_or((1, 22));
    let version = ((major as u32) << 16) | (minor as u32);
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let out_path = PathBuf::from(out_dir).join("sudo_api_version.rs");
    let contents = format!(
        "pub const SUDO_API_VERSION_MAJOR: u32 = {major};\n\
pub const SUDO_API_VERSION_MINOR: u32 = {minor};\n\
pub const SUDO_API_VERSION: u32 = {version};\n"
    );
    fs::write(out_path, contents).expect("write sudo_api_version.rs");

    println!("cargo:rerun-if-changed=/usr/include/sudo_plugin.h");
    println!("cargo:rerun-if-changed=/usr/local/include/sudo_plugin.h");

    println!("cargo:rerun-if-env-changed=OPENSSL_STATIC");
    if env::var("OPENSSL_STATIC").ok().as_deref() == Some("1") {
        println!("cargo:warning=OPENSSL_STATIC=1 requested; linking libcrypto/libssl statically");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=ssl");
    }
}

fn detect_sudo_api_version() -> Option<(u32, u32)> {
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let output = Command::new(cc)
        .args(["-dM", "-E", "-include", "sudo_plugin.h", "-"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut major: Option<u32> = None;
    let mut minor: Option<u32> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("#define SUDO_API_VERSION_MAJOR ") {
            major = rest.trim().parse::<u32>().ok();
        } else if let Some(rest) = line.strip_prefix("#define SUDO_API_VERSION_MINOR ") {
            minor = rest.trim().parse::<u32>().ok();
        }
    }
    match (major, minor) {
        (Some(maj), Some(min)) => Some((maj, min)),
        _ => None,
    }
}
