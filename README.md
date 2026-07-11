# mimir — the mimir platform CLI

A single, self-contained binary (no `kubectl`/`kubelogin` needed): gcloud-style **device-flow login**
(OIDC / RFC 8628), **RBAC-gated** operations, and **projects** as the unit of tenancy. No deployment
endpoints are baked in — the CLI is configured for your cluster.

## Install

**Homebrew (macOS / Linux):**
```sh
brew install nixie-tech-llc/tap/mimir
```

**Scoop (Windows):**
```powershell
scoop bucket add nixie https://github.com/Nixie-Tech-LLC/scoop-bucket
scoop install mimir
```

**Install script (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/Nixie-Tech-LLC/mimir-cli/main/install.sh | sh
```

**Go:**
```sh
go install github.com/Nixie-Tech-LLC/mimir-cli/cmd/mimir@latest
```

**Manual (all OSes):** download an archive from
[Releases](https://github.com/Nixie-Tech-LLC/mimir-cli/releases), extract (`.tar.gz` on Linux/macOS, `.zip`
on Windows), put `mimir` on your `PATH`. Every release ships `checksums.txt` (sha256). Verify: `mimir version`.

## Configure (once)

Point the CLI at your cluster's apiserver + Dex issuer. Your platform admin provides these values (or a
ready-made `~/.mimir/config.json`):
```sh
mimir configure \
  --server https://APISERVER_HOST:6443 --server-ca /path/to/cluster-ca.crt \
  --oidc-issuer https://DEX_ISSUER_HOST --oidc-client-id mimir-cli --oidc-ca /path/to/oidc-ca.crt
```
Env equivalents: `MIMIR_SERVER`, `MIMIR_SERVER_CA_FILE`, `MIMIR_OIDC_ISSUER`, `MIMIR_OIDC_CLIENT_ID`,
`MIMIR_OIDC_CA_FILE`, `MIMIR_INSECURE=1` (dev/self-signed).

## Use

```sh
mimir auth login                       # device flow: open the URL, approve in your IdP
mimir auth whoami                      # your email + groups (from the token)
mimir projects create acme --member you@corp.com --cpu 8 --memory 16Gi
mimir projects list
mimir projects delete acme
```

### kubectl integration (optional)
`mimir` is its own kubeconfig credential plugin, so `kubectl` can reuse the same login:
```yaml
users:
  - name: mimir
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: mimir
        args: ["auth", "get-token"]
```

## Build from source
```sh
git clone https://github.com/Nixie-Tech-LLC/mimir-cli && cd mimir-cli && go build -o mimir ./cmd/mimir
```
Stdlib-only — no external dependencies. Releases are cut with `vX.Y.Z` tags; cross-platform archives +
`checksums.txt` are published to GitHub Releases.
