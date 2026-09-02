#!/usr/bin/env bash
# Registers a nethsm key provider on a realm.
#
# The testbed runs `start-dev`, whose H2 database is in-memory, so realm configuration
# is lost whenever the Keycloak container is recreated. Re-run this after every
# `docker compose up --build`.
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8080}"
KC_USER="${KC_USER:-admin}"
KC_PASSWORD="${KC_PASSWORD:-admin}"
REALM="${REALM:-master}"
NAME="${NAME:-nethsm-rs256}"
KEY_PREFIX="${KEY_PREFIX:-kc-rsa}"
ALGORITHM="${ALGORITHM:-RS256}"
PRIORITY="${PRIORITY:-200}"

token() {
  curl -sf -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d "username=$KC_USER" -d "password=$KC_PASSWORD" \
    -d grant_type=password | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

TOKEN="$(token)"
[[ -n "$TOKEN" ]] || { echo "!! could not authenticate to $KC_URL" >&2; exit 1; }

echo "==> registering '$NAME' on realm '$REALM' (prefix '$KEY_PREFIX', $ALGORITHM, priority $PRIORITY)"

# parentId is deliberately omitted: Keycloak defaults it to the realm this endpoint
# addresses. Sending it by hand is a trap -- it must be the realm's internal UUID, and a
# component created with the realm *name* is accepted with 201 and then silently never
# consulted, so the provider looks registered while contributing no keys.
curl -sf -X POST "$KC_URL/admin/realms/$REALM/components" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$NAME\",\"providerId\":\"nethsm\",
       \"providerType\":\"org.keycloak.keys.KeyProvider\",
       \"config\":{\"priority\":[\"$PRIORITY\"],\"enabled\":[\"true\"],\"active\":[\"true\"],
                   \"keyPrefix\":[\"$KEY_PREFIX\"],\"algorithm\":[\"$ALGORITHM\"]}}" \
  && echo "==> created"

echo "==> realm keys:"
curl -sf -H "Authorization: Bearer $TOKEN" "$KC_URL/admin/realms/$REALM/keys"
echo
