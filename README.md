# VPN Manager

VPN Manager is a small Rust web application for generating self-contained OpenVPN client configs from editable templates. It integrates with a Minica certificate authority service to fetch CA material, issue client certificates, and embed the required certificates and keys into generated `.ovpn` files.

## Features

- Manage OpenVPN templates stored on disk.
- Define template placeholders such as `%server_host%`, `%server_port%`, or custom delimiters like `{{name}}`.
- Define template parameter metadata, including required fields, dropdown options, numeric ranges, and defaults.
- Configure Minica connection settings and certificate defaults.
- List available certificate authorities from Minica.
- Generate OpenVPN configs from a template, CA, client name, tags, and parameters.
- Browse, download, inspect, and delete generated OpenVPN configs.
- Use the same functionality through JSON APIs under `/vpnman/api`.
- Optional HTTP Basic Authentication.
- Reverse-proxy friendly base path under `/vpnman/`.
- Static UI assets, including Swagger UI, are vendored and embedded into the compiled binary.

## Configuration

The program reads `config.yaml` by default. You can pass another file with `--config` or `-c`.

```yaml
data_dir: data
bind:
  host: 127.0.0.1
  port: 8080
basic_auth:
  enabled: false
  username: admin
  password: change-me
```

`basic_auth` may be omitted entirely. If omitted, or if `enabled: false`, authentication is disabled.

The app exits at startup if the config file is missing, invalid, or fails validation.

## Running

```bash
cargo run
```

Or with an explicit config:

```bash
cargo run -- --config config.yaml
cargo run -- -c config.yaml
```

Open:

```text
http://127.0.0.1:8080/vpnman/
```

`/` redirects to `/vpnman/`.

## Web UI

- `Home`: summary of templates, generated configs, and CA configuration status.
- `OpenVPN Configs`: generated profile list, details, raw `.ovpn`, download, and delete.
- `OpenVPN Templates`: create, edit, and delete OpenVPN templates.
- `Certificate Authority Config`: Minica connection settings, CA list, certificate defaults, save/test/reset controls.
- `Swagger Explorer`: real Swagger UI at `/vpnman/api/swagger`.

## Minica Settings

Minica settings are stored under the configured data directory:

```text
data/config/minica.yaml
```

The default CA is a UI convenience and an API fallback. The API can issue configs against any valid CA ID. If `ca_id` is omitted from the issue-config API, the saved default CA ID is used.

## API

All API routes are under `/vpnman/api`.

Responses use this envelope shape:

```json
{
  "success": true,
  "error_code": "",
  "error_message": "",
  "data": {}
}
```

Endpoints:

- `GET /vpnman/api/templates`
- `GET /vpnman/api/cas`
- `POST /vpnman/api/configs`
- `GET /vpnman/api/profiles`
- `GET /vpnman/api/profiles/{id}`
- `GET /vpnman/api/openapi.json`
- `GET /vpnman/api/swagger`
- `GET /vpnman/api/swagger-ui/...` embedded Swagger UI assets

Example issue request:

```json
{
  "template_id": "template-id",
  "ca_id": "ca-id",
  "client_name": "laptop-01",
  "tags": ["laptop", "team=engineering"],
  "parameters": {
    "proto": "udp",
    "server_host": "vpn.example.com",
    "server_port": "1194"
  }
}
```

`ca_id` is optional. If omitted or blank, the configured default CA ID is used. Template parameter validation is the same as the web UI.

## Storage

The configured `data_dir` contains:

```text
config/
  minica.yaml
templates/
  <template-id>/
    metadata.yaml
    template.ovpn
profiles/
  <profile-id>/
    metadata.yaml
    profile.ovpn
```

Generated OpenVPN configs include private keys. Treat the data directory as sensitive.

## Security Notes

- Basic Auth is optional and configured in `config.yaml`.
- Requests are checked for CR/LF characters in URI/header data.
- Unsafe browser requests (`POST`, `PUT`, `PATCH`, `DELETE`) are protected with CSRF origin checks. Cross-site browser submissions are rejected. Same-origin UI/API calls are allowed, and non-browser API clients without browser origin headers can use Basic Auth normally.
- When VPN Manager writes to Minica, it first requests Minica's CSRF token from `/api/csrf` and sends it back to Minica in the `X-CSRF-Token` header for certificate create/delete calls.
- Minica credentials are stored in plaintext YAML by design for this local management app.
- Deleting a generated OpenVPN config removes local files only. It does not revoke or delete the certificate in Minica.
