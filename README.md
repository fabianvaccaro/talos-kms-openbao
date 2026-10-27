# talos-kms-openbao

A small [Talos Linux](https://www.talos.dev) KMS endpoint backed by an
[OpenBao](https://openbao.org) (or HashiCorp Vault) **transit** key.

Talos can encrypt its disks with LUKS2 and hand each disk's passphrase to a
network KMS (`keys: - kms: endpoint: ...`). The KMS seals the passphrase once at
install time and unseals it on every boot. If the node cannot reach the KMS, the
disk stays locked. This service implements that gRPC API
(`sidero.kms.KMSService`, from [siderolabs/kms-client](https://github.com/siderolabs/kms-client))
and delegates the cryptography to OpenBao.

About 500 lines of Go (plus tests), with no Vault SDK. Small enough to audit in one sitting.

## What it does

- **Seal**: checks that the node UUID is canonical and the passphrase is
  32 bytes. Then it encrypts `magic ‖ node-uuid ‖ passphrase` with
  `transit/encrypt/<key>` and returns OpenBao's ciphertext.
- **Unseal**: decrypts with `transit/decrypt/<key>`. It returns the passphrase
  only if the UUID inside the authenticated plaintext matches the UUID of the
  caller.
- **Never** sees or stores the key itself: the key is created non-exportable in
  OpenBao. Every request appears in OpenBao's audit log.
- Optionally admits only enrolled nodes (`-allowed-nodes FILE`, one UUID per
  line, `#` comments). Unknown nodes get PermissionDenied and a warning in the
  log; an unreadable file denies everyone (fails closed). The file is re-read
  on every request, so enrolling a node is editing a file.
- Renews its own periodic token every hour.

## Threat model, briefly

What protects the data is **reachability plus the key staying in OpenBao**:

- A stolen disk, or a node booted outside the trusted network, cannot get its
  passphrase.
- Revoking the token, sealing OpenBao or cutting the network path locks every
  disk at its next boot.

The node-UUID binding and the allowlist stop one node from unsealing another
node's blob, and make a request from an unexpected node visible. Neither is
authentication: SMBIOS UUIDs
are not secret. So expose this service only on a network path you control, for
example a dedicated VLAN or a WireGuard tunnel plus firewall rules, and serve it
over TLS.

## Setup (OpenBao side)

```sh
bao secrets enable transit
bao write -f transit/keys/talos-kms type=aes256-gcm96          # exportable=false by default
bao policy write talos-kms - <<'EOF'
path "transit/encrypt/talos-kms" { capabilities = ["update"] }
path "transit/decrypt/talos-kms" { capabilities = ["update"] }
EOF
```

Mint the service token with `deploy/mint-service-token.sh` (periodic, orphan,
that policy only, 1 year by default and renewed hourly by the service). It is
meant for a server whose root token is already revoked, on OpenBao ≥ 2.5.3,
where the unauthenticated generate-root endpoints are off by default and only
registered at startup. With a quorum of unseal keys typed once, it enables those
endpoints, restarts and unseals OpenBao, generates a root token, mints the
service token, revokes the root token, then restores the config, restarts and
unseals again. Keys and the root token stay in the script's memory: they are
never printed, written to disk or put on a command line. Set `BAO_ADDR` and
friends in `/etc/talos-kms/mint.env`.

## Run

```sh
talos-kms-openbao \
  -listen=:4050 -tls-cert=tls.crt -tls-key=tls.key \
  -bao-addr=https://127.0.0.1:8200 -bao-ca=bao-ca.crt \
  -bao-mount=transit -bao-key=talos-kms \
  -token-file=/etc/talos-kms/bao-token \
  -allowed-nodes=/etc/talos-kms/allowed-nodes
```

`deploy/talos-kms-openbao.service` is a hardened systemd unit.

## Talos side

```yaml
apiVersion: v1alpha1
kind: VolumeConfig
name: STATE        # and EPHEMERAL
encryption:
  provider: luks2
  keys:
    - slot: 0
      kms:
        endpoint: https://kms.example.internal:4050
```

If the server certificate comes from a private CA, add the CA with a
`TrustedRootsConfig` document.

## Build and test

```sh
go test -race ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" ./cmd/talos-kms-openbao
```

## License

MIT
