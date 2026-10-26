#!/usr/bin/env bash
# Mint the periodic, transit-only token talos-kms-openbao runs with.
#
# OpenBao's root token is revoked after setup, so this script regenerates one
# from a quorum of unseal keys, uses it for exactly one call, and revokes it.
# The root token and the keys are never printed, written to disk or passed on
# a command line: keys are read silently from the terminal and piped to bao,
# the root token lives only in this process's environment.
#
# Run as root on the OpenBao host, interactively:
#   sudo ./mint-service-token.sh
set -euo pipefail

: "${BAO_ADDR:=https://127.0.0.1:8200}"
: "${BAO_CACERT:=/etc/openbao/tls/ca.crt}"
: "${KMS_POLICY:=talos-kms}"
: "${KMS_TOKEN_PERIOD:=720h}"
: "${KMS_TOKEN_FILE:=/etc/talos-kms/bao-token}"
: "${KMS_USER:=talos-kms}"
export BAO_ADDR BAO_CACERT

[[ -t 0 ]] || { echo "run this interactively: unseal keys are read from the terminal" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

umask 077
started=0
cancel() {
  unset BAO_TOKEN
  if [[ $started -eq 1 ]]; then
    bao operator generate-root -cancel >/dev/null 2>&1 || true
  fi
}
trap cancel EXIT

if [[ $(bao operator generate-root -status -format=json | jq -r .started) == true ]]; then
  echo "a root generation is already in progress; cancel it first: bao operator generate-root -cancel" >&2
  exit 1
fi

otp=$(bao operator generate-root -generate-otp)
nonce=$(bao operator generate-root -init -otp="$otp" -format=json | jq -r .nonce)
started=1
required=$(bao operator generate-root -status -format=json | jq -r .required)

echo "Root token generation started (nonce ${nonce:0:8}…). ${required} unseal keys needed."
encoded=""
for ((i = 1; i <= required; i++)); do
  read -rsp "Unseal key ${i}/${required}: " key
  echo
  out=$(printf '%s' "$key" | bao operator generate-root -nonce="$nonce" -format=json -)
  unset key
  if [[ $(jq -r .complete <<<"$out") == true ]]; then
    encoded=$(jq -r .encoded_token <<<"$out")
    break
  fi
done
[[ -n $encoded ]] || { echo "generation did not complete" >&2; exit 1; }
started=0

BAO_TOKEN=$(bao operator generate-root -decode="$encoded" -otp="$otp")
export BAO_TOKEN
unset encoded otp

trap 'bao token revoke -self >/dev/null 2>&1 || echo "WARNING: revoke the generated root token by hand" >&2; unset BAO_TOKEN' EXIT

created=$(bao token create -orphan -period="$KMS_TOKEN_PERIOD" -policy="$KMS_POLICY" \
  -display-name="talos-kms-openbao" -format=json)

install -d -m 0750 -o root -g "$KMS_USER" "$(dirname "$KMS_TOKEN_FILE")"
tmp=$(mktemp "${KMS_TOKEN_FILE}.XXXXXX")
jq -r .auth.client_token <<<"$created" >"$tmp"
chown "$KMS_USER:$KMS_USER" "$tmp"
chmod 0400 "$tmp"
mv -f "$tmp" "$KMS_TOKEN_FILE"

echo "Service token written to ${KMS_TOKEN_FILE}"
echo "  accessor: $(jq -r .auth.accessor <<<"$created")"
echo "  policies: $(jq -r '.auth.policies | join(",")' <<<"$created")  period: ${KMS_TOKEN_PERIOD}"
unset created
echo "Root token revoked on exit."
