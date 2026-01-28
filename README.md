# sudo-jwt-approval (minimal)

Minimal sudo approval plugin that enforces a short-lived JWT stored in a file. This runs after sudoers and can further restrict access.

## Build

```sh
make
```

Build output: `sudo_jwt_approval.so`

Dependencies:
- sudo development headers (`sudo_plugin.h`)
- OpenSSL (`libcrypto`)

## Install (example)

```sh
sudo install -m 0755 sudo_jwt_approval.so /usr/local/libexec/sudo/
sudo install -m 0644 sudo-jwt-policy.conf /etc/sudo-jwt-policy.conf
```

Configure sudoers as the policy plugin and add the approval plugin in `/etc/sudo.conf`:

```
Plugin sudoers_policy sudoers.so
Plugin sudo_jwt_approval sudo_jwt_approval.so config=/etc/sudo-jwt-policy.conf
```

The approval plugin runs after sudoers. It can only restrict what sudoers already allows.

## Config

See `sudo-jwt-policy.conf` for a minimal example. Required keys:

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
- `command_allowlist` (comma-separated list of absolute command paths that require JWT; if set, other commands bypass the plugin)
- `audience` may be a quoted string or an absolute path to a file containing the audience value

## JWT requirements

This plugin expects:

- `iss` matches `issuer`
- `aud` matches `audience` (string or array)
- `exp` and `iat` present and valid
- `scope` contains the required scope (string or array)
- optional `host` matches if configured

Algorithms supported: `RS256` and `EdDSA`.

## Runtime flow (summary)

1. Jenkins writes a JWT to the configured token file.
2. sudoers allows the command based on sudoers rules.
3. The approval plugin validates the token.
4. If claims match, sudo allows the command.

## Notes

- The token file must not be group/world writable.
- Token size is capped at 16KB.
- Clock skew tolerance: 60 seconds.
- If `require_jwt=false`, missing token allows sudoers to decide; invalid tokens still deny.
