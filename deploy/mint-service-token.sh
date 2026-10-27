#!/usr/bin/env bash
# Mint the periodic, transit-only token talos-kms-openbao runs with.
#
# OpenBao's root token is revoked after setup, and since v2.5.3 the
# unauthenticated generate-root endpoints are off by default and only
# registered at startup. So this script, with a quorum of unseal keys typed
# once:
#   1. enables those endpoints in the config and restarts OpenBao, unseals it;
#   2. generates a root token, mints the service token, revokes the root token;
#   3. restores the original config, restarts OpenBao again and unseals it.
# Keys and the root token are never printed, written to disk or put on a
# command line; they live only in this process's memory.
#
# Run as root on the OpenBao host, interactively:
#   sudo ./mint-service-token.sh
set -euo pipefail

# Host-specific overrides, since sudo drops the caller's environment.
MINT_ENV=${MINT_ENV:-/etc/talos-kms/mint.env}
# shellcheck source=/dev/null
[[ -r $MINT_ENV ]] && . "$MINT_ENV"

: "${BAO_ADDR:=https://127.0.0.1:8200}"
: "${BAO_CACERT:=/etc/openbao/tls/ca.crt}"
: "${BAO_CONFIG:=/etc/openbao/openbao.hcl}"
: "${BAO_SERVICE:=openbao}"
: "${KMS_POLICY:=talos-kms}"
: "${KMS_TOKEN_PERIOD:=8760h}"
: "${KMS_TOKEN_FILE:=/etc/talos-kms/bao-token}"
: "${KMS_USER:=talos-kms}"
export BAO_ADDR BAO_CACERT

[[ -t 0 ]] || { echo "run this interactively: unseal keys are read from the terminal" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
umask 077

api() { # method path [json-on-stdin]
  curl -sS --fail-with-body --cacert "$BAO_CACERT" -X "$1" -H 'Content-Type: application/json' \
    --data @- "${BAO_ADDR}/v1/$2"
}

wait_up() {
  for _ in $(seq 60); do
    curl -s --cacert "$BAO_CACERT" "${BAO_ADDR}/v1/sys/seal-status" >/dev/null && return 0
    sleep 1
  done
  echo "OpenBao did not come back" >&2
  return 1
}

unseal() {
  local k
  [[ $(api GET sys/seal-status </dev/null | jq -r .sealed) == true ]] || return 0
  for k in "${keys[@]}"; do
    printf '%s' "$k" | jq -Rnc '{key: input}' | api PUT sys/unseal >/dev/null
  done
  [[ $(api GET sys/seal-status </dev/null | jq -r .sealed) == false ]] || { echo "still sealed: wrong keys?" >&2; return 1; }
}

restart_and_unseal() {
  systemctl restart "$BAO_SERVICE"
  wait_up
  unseal
}

required=$(api GET sys/seal-status </dev/null | jq -r .t) || { echo "cannot reach OpenBao at ${BAO_ADDR}" >&2; exit 1; }
grep -q disable_unauthed_generate_root_endpoints "$BAO_CONFIG" && { echo "$BAO_CONFIG already sets disable_unauthed_generate_root_endpoints; refusing" >&2; exit 1; }

keys=()
for ((i = 1; i <= required; i++)); do
  read -rsp "Unseal key ${i}/${required}: " key
  echo
  keys+=("$key")
done
unset key

backup="${BAO_CONFIG}.pre-mint"
cp -p "$BAO_CONFIG" "$backup"
restored=0
finish() {
  status=$?
  unset BAO_TOKEN
  if [[ $restored -eq 0 ]]; then
    api DELETE sys/generate-root/attempt </dev/null >/dev/null 2>&1 || true
    mv -f "$backup" "$BAO_CONFIG"
    echo "Restoring the original OpenBao config and restarting…"
    restart_and_unseal || echo "WARNING: OpenBao may be sealed; unseal it by hand" >&2
  fi
  keys=()
  exit "$status"
}
trap finish EXIT

# 1. Enable the unauthenticated generate-root endpoints for this run only.
sed -i 's/^\(\s*\)tls_min_version.*/&\n\1disable_unauthed_generate_root_endpoints = false/' "$BAO_CONFIG"
grep -q 'disable_unauthed_generate_root_endpoints = false' "$BAO_CONFIG" || { echo "could not patch listener" >&2; exit 1; }
echo "Restarting OpenBao with generate-root enabled…"
restart_and_unseal

# 2. Root token → service token → revoke root token.
api DELETE sys/generate-root/attempt </dev/null >/dev/null 2>&1 || true
init=$(echo '{}' | api PUT sys/generate-root/attempt)
nonce=$(jq -r .nonce <<<"$init")
otp=$(jq -r .otp <<<"$init")
encoded=""
for k in "${keys[@]}"; do
  out=$(printf '%s' "$k" | jq -Rnc --arg nonce "$nonce" '{key: input, nonce: $nonce}' | api PUT sys/generate-root/update)
  if [[ $(jq -r .complete <<<"$out") == true ]]; then
    encoded=$(jq -r .encoded_token <<<"$out")
    break
  fi
done
unset k
[[ -n $encoded ]] || { echo "root generation did not complete" >&2; exit 1; }

# Decode locally (the bao CLI's -decode asks the server for the OTP length via
# the authenticated endpoint): token = base64raw(encoded) XOR otp.
BAO_TOKEN=$(printf '%s\n%s\n' "$encoded" "$otp" | python3 -I -c '
import base64, sys
enc, otp = sys.stdin.read().split("\n")[:2]
raw = base64.b64decode(enc + "=" * (-len(enc) % 4))
if len(raw) != len(otp):
    sys.exit("encoded token and OTP lengths differ")
sys.stdout.write(bytes(a ^ b for a, b in zip(raw, otp.encode())).decode())')
export BAO_TOKEN
unset encoded otp init out

created=$(bao token create -orphan -period="$KMS_TOKEN_PERIOD" -policy="$KMS_POLICY" \
  -display-name="talos-kms-openbao" -format=json)
bao token revoke -self >/dev/null
unset BAO_TOKEN

install -d -m 0750 -o root -g "$KMS_USER" "$(dirname "$KMS_TOKEN_FILE")"
tmp=$(mktemp "${KMS_TOKEN_FILE}.XXXXXX")
jq -r .auth.client_token <<<"$created" >"$tmp"
chown "$KMS_USER:$KMS_USER" "$tmp"
chmod 0400 "$tmp"
mv -f "$tmp" "$KMS_TOKEN_FILE"
accessor=$(jq -r .auth.accessor <<<"$created")
unset created

# 3. Back to the hardened config.
mv -f "$backup" "$BAO_CONFIG"
restored=1
echo "Restoring the original OpenBao config and restarting…"
restart_and_unseal
keys=()

echo
echo "Done."
echo "  service token: ${KMS_TOKEN_FILE} (accessor ${accessor}, policy ${KMS_POLICY}, period ${KMS_TOKEN_PERIOD})"
echo "  root token: revoked"
echo "  OpenBao: original config, unsealed"
