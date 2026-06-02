# sudo-awesome-jwt

[![CI](https://github.com/sippy/sudo_awesome_jwt/actions/workflows/build.yml/badge.svg)](https://github.com/sippy/sudo_awesome_jwt/actions/workflows/build.yml)

A sudo approval + policy plugin that authorizes sudo commands with a short-lived JWT stored in a file.

The plugin supports two deployment modes:

- **Approval mode:** keep an existing sudoers rule and require a valid JWT as an additional authorization factor. In this mode sudoers still decides the baseline permission, and `sudo-awesome-jwt` acts like command-scoped JWT "2FA" for entries that would otherwise be permanently allowed.
- **Policy mode:** use the JWT plugin as the sudo policy plugin. In this mode a permanent sudoers command entry can be replaced by a short-lived token that names the command, runas identity, and environment permission for one job or workflow.

This is intended for automation systems such as CI workers where a trusted signer can issue narrow, time-limited sudo capability tokens instead of leaving broad standing sudo permissions on disk.

## Build

```sh
make
```

Build output: `sudo_awesome_jwt.so`

Dependencies:
- sudo development headers (`sudo_plugin.h`)
- OpenSSL (`libcrypto`)

Build notes:
- Symbols are hidden by default (`-fvisibility=hidden`); `src/exports.map` exports `approval` and `policy` via a linker version script.
- To link against static OpenSSL (if static libs are installed), build with:
  ```
  make OPENSSL_STATIC=1
  ```
  You can also override `OPENSSL_LIBS` directly if your platform needs different flags.

## Rust version

An alternate Rust implementation lives in `rust/` and produces a cdylib with the same exported symbols (`approval`, `policy`).

Build:
```sh
cd rust
cargo build --release
```

Output:
- `rust/target/release/libsudo_awesome_jwt_rust.so`

Notes:
- The C and Rust implementations are expected to provide the same sudo plugin functionality and accept the same configuration and JWT policy format.
- Supports `RS256` and `EdDSA` (Ed25519/Ed448) like the C version.
- Still reads the same `sudo_awesome_jwt.conf` file and uses the same config keys.
- Symbol exports are restricted via `src/exports.map` and `rust/build.rs`.
- To request static OpenSSL when building the Rust version, set:
  ```
  OPENSSL_STATIC=1 cargo build --release
  ```
  Static `libcrypto`/`libssl` must be available on the system.

## Install (example)

Install the configuration file:

```sh
sudo install -m 0644 sudo_awesome_jwt.conf /usr/local/etc/sudo_awesome_jwt.conf
```

Install one plugin implementation.

C build:

```sh
sudo install -m 0755 sudo_awesome_jwt.so /usr/local/libexec/sudo/sudo_awesome_jwt.so
```

Rust build:

```sh
sudo install -m 0755 rust/target/release/libsudo_awesome_jwt_rust.so /usr/local/libexec/sudo/sudo_awesome_jwt.so
```

The sudo.conf examples below use `sudo_awesome_jwt.so` because sudo resolves plugin names from its configured plugin directory. Use a full path only if your installation requires it.

### Approval mode

With the default sudoers policy already active, add `sudo-awesome-jwt` as an approval plugin in `/etc/sudo.conf`:

```
Plugin approval sudo_awesome_jwt.so config=/usr/local/etc/sudo_awesome_jwt.conf
```

The approval plugin runs after sudoers. It can only restrict what sudoers already allows.

### Policy mode

Use the JWT plugin as the primary policy plugin when the token should replace a standing sudoers command rule:

```
Plugin policy sudo_awesome_jwt.so config=/usr/local/etc/sudo_awesome_jwt.conf
```

The shared object exports both `approval` and `policy`; choose one mode in `sudo.conf` for the authorization model you want.

## Plugin options

Options are passed in `sudo.conf` on the `Plugin` line and apply to both approval and policy plugins:

- `config=/path/to/sudo_awesome_jwt.conf` (optional; defaults to `/usr/local/etc/sudo_awesome_jwt.conf`)
- `debug` (enable debug logging)
- `debug=1|0|true|false|yes|no` (explicitly enable/disable debug logging)

Approval-mode example:

```
Plugin approval sudo_awesome_jwt.so config=/usr/local/etc/sudo_awesome_jwt.conf debug=1
```

Policy-mode example:

```
Plugin policy sudo_awesome_jwt.so config=/usr/local/etc/sudo_awesome_jwt.conf debug=1
```

## Config

See `sudo_awesome_jwt.conf` for an example configuration. Required keys:

- `token_file`
- `public_key`
- `issuer`
- `audience`

Optional:

- `scope` (default: `sudo`)
- `host`
- `max_ttl` (default: 300 seconds)
- `require_tty` (default: false)
- `require_jwt` (default: true)
- `only_user` (if set, enforce JWT only for this user)
- `only_uid` (if set, enforce JWT only for this uid)
- `${user}` and `${uid}` are expanded in config values. Single-quote a value to disable expansion.
- `audience` may be a quoted string or an absolute path to a file containing the audience value

## JWT requirements

This plugin expects:

- `iss` matches `issuer`
- `aud` matches `audience` (string or array)
- `exp` and `iat` present and valid
- `scope` contains the required scope (string or array)
- `sub` matches the invoking user
- optional `host` matches if configured

## JWT command policy

The JWT must include a `cmds` array describing allowed commands for this token. Each entry is an object with:

- `path` (absolute command path)
- optional `runas_user`
- optional `runas_uid`
- optional `runas_gid`
- optional `runas_group`
- optional `setenv` (allows `-E`/`--preserve-env` or environment assignments when true; rejects them when false or omitted)

If you need to allow multiple runas groups for the same command, add multiple entries (one per group).

If `cmds` is missing or the requested command does not match any entry, the request is denied.

Example JWT payload (claims):

```json
{
  "iss": "ci-signer",
  "aud": "sudo-awesome-jwt",
  "sub": "jenkins",
  "iat": 1738360000,
  "exp": 1738360300,
  "scope": "sudo",
  "cmds": [
    {
      "path": "/usr/local/bin/git",
      "runas_user": "maintenance"
    },
    {
      "path": "/home/maintenance/scripts/web_update.py",
      "runas_user": "www-root",
      "runas_group": "www"
    },
    {
      "path": "/home/maintenance/scripts/system_upgrade.sh",
      "runas_user": "root",
      "runas_uid": 0,
      "runas_gid": 0,
      "setenv": true
    }
  ]
}
```

Algorithms supported: `RS256` and `EdDSA`.

## Runtime flow

Approval mode:

1. The automation system writes a JWT to the configured token file.
2. sudoers allows the command based on the existing sudoers rule.
3. The approval plugin validates the JWT claims and command policy.
4. sudo runs the command only if both sudoers and the JWT approve it.

Policy mode:

1. The automation system writes a JWT to the configured token file.
2. sudo calls the JWT policy plugin directly.
3. The policy plugin validates the JWT claims and command policy.
4. sudo runs the command if the token permits the requested command, runas identity, and environment behavior.

## Notes

- The token file must not be group/world writable.
- Token size is capped at 16KB.
- Clock skew tolerance: 60 seconds.
- If `require_jwt=false`, a missing token allows the request to continue. In approval mode, sudoers still decides. In policy mode, the JWT policy plugin allows the request. Invalid tokens still deny.
