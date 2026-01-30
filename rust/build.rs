use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let map_path = PathBuf::from(manifest_dir).join("../src/exports.map");
    if map_path.exists() {
        println!("cargo:rustc-link-arg=-Wl,--version-script={}", map_path.display());
    }

    println!("cargo:rerun-if-env-changed=OPENSSL_STATIC");
    if env::var("OPENSSL_STATIC").ok().as_deref() == Some("1") {
        println!("cargo:warning=OPENSSL_STATIC=1 requested; linking libcrypto/libssl statically");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=ssl");
    }
}
