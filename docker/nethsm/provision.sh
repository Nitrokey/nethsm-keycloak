#!/usr/bin/env bash
# Provisions the NetHSM test container from factory state into a usable dev fixture:
# provisioned + unlocked, one Operator user, one RSA key per signing algorithm family.
#
# Idempotent: re-running against an already-provisioned NetHSM is a no-op.
set -euo pipefail

NETHSM_URL="${NETHSM_URL:-https://localhost:8443/api/v1}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSPHRASE="${ADMIN_PASSPHRASE:-AdminAdminAdmin}"
UNLOCK_PASSPHRASE="${UNLOCK_PASSPHRASE:-UnlockUnlockUnlock}"
OPERATOR_USER="${OPERATOR_USER:-keycloak}"
OPERATOR_PASSPHRASE="${OPERATOR_PASSPHRASE:-KeycloakKeycloak}"

# The test image ships a self-signed cert; -k is correct here and only here.
curl_json() { curl -sk --fail-with-body -H 'Content-Type: application/json' "$@"; }
as_admin() { curl_json -u "$ADMIN_USER:$ADMIN_PASSPHRASE" "$@"; }

echo "==> waiting for $NETHSM_URL"
for _ in $(seq 1 60); do
  curl -sk -o /dev/null "$NETHSM_URL/health/state" && break
  sleep 1
done

state="$(curl -sk "$NETHSM_URL/health/state" | sed -n 's/.*"state" *: *"\([^"]*\)".*/\1/p')"
echo "==> state: ${state:-unreachable}"

case "$state" in
  Unprovisioned)
    echo "==> provisioning"
    curl_json -X POST "$NETHSM_URL/provision" -d "$(cat <<JSON
{"unlockPassphrase":"$UNLOCK_PASSPHRASE",
 "adminPassphrase":"$ADMIN_PASSPHRASE",
 "systemTime":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
)"
    ;;
  Locked)
    echo "==> unlocking"
    curl_json -X POST "$NETHSM_URL/unlock" -d "{\"passphrase\":\"$UNLOCK_PASSPHRASE\"}"
    ;;
  Operational) echo "==> already operational" ;;
  *) echo "!! unexpected state '${state:-}'" >&2; exit 1 ;;
esac

# Without this a restarted NetHSM comes back Locked and needs the unlock passphrase.
# The fail-closed end-to-end test stops and starts the container, so the fixture has to
# return to Operational on its own. Appropriate for a disposable test container only.
echo "==> enabling unattended boot"
as_admin -X PUT "$NETHSM_URL/config/unattended-boot" -d '{"status":"on"}' || echo "   (already on)"

echo "==> operator user '$OPERATOR_USER'"
as_admin -X PUT "$NETHSM_URL/users/$OPERATOR_USER" -d "$(cat <<JSON
{"realName":"Keycloak","role":"Operator","passphrase":"$OPERATOR_PASSPHRASE"}
JSON
)" || echo "   (exists)"

# One key per NetHSM sign mode Keycloak needs. Key ids match the ID pattern
# ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ so they can be typed straight into the admin console.
generate_key() {
  local id="$1" type="$2" length="$3" mechanisms="$4"
  echo "==> key '$id' ($type $mechanisms)"
  local body="{\"id\":\"$id\",\"type\":\"$type\",\"mechanisms\":[$mechanisms]"
  [[ -n "$length" ]] && body="$body,\"length\":$length"
  body="$body}"
  as_admin -X POST "$NETHSM_URL/keys/generate" -d "$body" || echo "   (exists)"
}

# RS256/384/512 -- SignMode PKCS1, digest must arrive DigestInfo-prefixed.
generate_key kc-rsa-pkcs1 RSA 2048 '"RSA_Signature_PKCS1"'
# PS256/384/512 -- SignMode PSS_SHA*, bare digest.
generate_key kc-rsa-pss RSA 2048 '"RSA_Signature_PSS_SHA256","RSA_Signature_PSS_SHA384","RSA_Signature_PSS_SHA512"'
# RSA-OAEP / RSA-OAEP-256 -- DecryptMode OAEP_SHA1 / OAEP_SHA256, for unwrapping a JWE
# content encryption key. NetHSM names only the digest and says nothing about the mask
# generation function, so NetHsmContractIT pins that MGF1 tracks the digest.
generate_key kc-rsa-oaep RSA 2048 '"RSA_Decryption_OAEP_SHA1","RSA_Decryption_OAEP_SHA256"'

# Two generations of the same signing key, for the rotation test.
generate_key kc-rot-2026a RSA 2048 '"RSA_Signature_PKCS1"'
generate_key kc-rot-2026b RSA 2048 '"RSA_Signature_PKCS1"'

# ES256/384/512 -- SignMode ECDSA. The curve alone determines the algorithm. NetHSM
# returns ASN.1 DER, which has to be converted to fixed-width R||S for JOSE.
generate_key kc-ec-p256 EC_P256 '' '"ECDSA_Signature"'
generate_key kc-ec-p384 EC_P384 '' '"ECDSA_Signature"'
generate_key kc-ec-p521 EC_P521 '' '"ECDSA_Signature"'
# EdDSA -- SignMode EdDSA, takes the raw message, returns 64-byte r||s (already JOSE-shaped).
generate_key kc-ed25519 Curve25519 '' '"EdDSA_Signature"'

echo
echo "==> keys:"
as_admin "$NETHSM_URL/keys"
echo
echo "==> ready. operator credentials: $OPERATOR_USER / $OPERATOR_PASSPHRASE"
