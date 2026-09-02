# Keycloak Provider for NetHSM

A Keycloak key provider that natively integrates with [Nitrokey NetHSM](https://www.nitrokey.com/products/nethsm)
to perform key operations (e.g. signing) while private keys never leave the HSM.

Status: **RSA signing works.** A Keycloak access token signed inside a NetHSM
verifies against the realm's published JWKS. RS256/384/512 and PS256/384/512 are
implemented; EC and Ed25519 are added separately.

## Quality Warning

**This project has been developed and reviewed entirely by an AI. It has been tested successfully
by unit tests and integration tests. The code has not been reviewed by a human yet and therefore
use it at your own risk.**

## Configuration

Two layers. The connection and the Operator credential are server-wide, ops-owned and
secret; each realm only says which key ids it claims.

### Server (`conf/keycloak.conf`, or `KC_SPI_KEYS__NETHSM__*`)

| Option | Default | Meaning |
|---|---|---|
| `spi-keys--nethsm--url` | — | API base including `/api/v1`. Comma-separated for a cluster; tried round-robin |
| `spi-keys--nethsm--username` | — | NetHSM user with the **Operator** role |
| `spi-keys--nethsm--passphrase` | — | min 10 characters |
| `spi-keys--nethsm--tls-fingerprints` | — | comma-separated SHA-256 certificate pins |
| `spi-keys--nethsm--tls-insecure` | `false` | disables verification; development only |
| `spi-keys--nethsm--timeout-seconds` | `10` | per request, once connected |
| `spi-keys--nethsm--connect-timeout-seconds` | `3` | to establish a connection; bounds how long an unreachable NetHSM holds a request thread |
| `spi-keys--nethsm--retries` | `2` | extra attempts per URL |
| `spi-keys--nethsm--retry-delay-ms` | `200` | between attempts |
| `spi-keys--nethsm--max-connections` | `20` | connection pool bound |
| `spi-keys--nethsm--discovery-cache-seconds` | `300` | how long discovered keys stay usable |

Omitting `url` leaves the provider registered but inert, so the jar is safe to ship in an
image that has no NetHSM.

An **Operator** credential is all this needs: the key operations Keycloak performs work
with it, and generating keys happens out of band. Nothing here checks the role, so keeping
Administrator out of the server configuration is least privilege to apply rather than a
guarantee this extension enforces.

Pinning replaces hostname verification, because a pinned NetHSM certificate is usually
self-signed with a CN that does not match the address Keycloak uses.

### Realm (*Realm Settings → Keys → Providers → nethsm*)

| Setting | Meaning |
|---|---|
| Key ID prefix | every NetHSM key whose id starts with this is published by this realm |
| Algorithm | which algorithm the keys are published under |
| Priority / Enabled / Active | standard Keycloak key provider settings |

One component means one algorithm, mirroring Keycloak's own providers. A NetHSM
`RSA_Signature_PKCS1` key is hash-agnostic and can serve RS256, RS384 or RS512, so the
choice is made here; a PSS key only appears under the algorithm its mechanism names.
Keys that cannot serve the chosen algorithm are skipped, so pointing a prefix at a mixed
set is fine.

`kid` is the NetHSM key id: stable across restarts and cluster nodes, which a generated
id could not be under auto-discovery. Do not point two components at the same key with
different algorithms — they would publish two JWKS entries under one `kid`.

## Algorithm mapping

Derived from each key's own `type` and `mechanisms`, so no algorithm is configured per
key — only the RS256/384/512 choice for a hash-agnostic PKCS1 key.

| Keycloak alg | NetHSM key type | `SignMode` | Note | |
|---|---|---|---|---|
| RS256/384/512 | RSA | `PKCS1` | send the digest **prefixed with the DigestInfo header** | ✅ |
| PS256/384/512 | RSA | `PSS_SHA256/384/512` | send the bare digest | ✅ |
| ES256/384/512 | EC_P256/384/521 | `ECDSA` | returns ASN.1 DER; JOSE needs fixed-width R‖S | planned |
| EdDSA | Curve25519 | `EdDSA` | send the raw message; returns 64-byte r‖s, already JOSE-shaped | planned |

## Known limitations

- **A cold start against an unreachable NetHSM falls back to a software key.** If a
  provider yields no keys, `DefaultKeyManager` logs *"No keys found for realm={0} and
  algorithm={1} for use={2}. Generating keys."* and generates one, after which Keycloak
  keeps issuing tokens signed outside the HSM. Discovery results are cached and never
  evicted on failure, so this cannot happen after a transient outage — but a Keycloak
  that starts while NetHSM is down or `Locked` has nothing cached to serve. Watch for
  that log line; hardening this is planned separately.
- **Signing only.** The framework abstracts `SignatureProvider`, not
  `CekManagementProvider`, so HSM-backed RSA-OAEP for encrypted tokens (JWE) is not
  covered. NetHSM supports OAEP decrypt, so this is buildable, but it is net-new work in
  the framework layer.
- **OID4VC credential issuance will not use the HSM.** `KeyWrapper.cloneKey()` hardcodes
  `new KeyWrapper()` and so erases the `HsmKeyWrapper` subtype that dispatch relies on.
  In Keycloak 26.7.3 its only caller is
  `org.keycloak.protocol.oid4vc.issuance.signing.AbstractCredentialSigner`; OIDC and SAML
  are unaffected.
- **`HS*` algorithms are not registered** — symmetric keys are out of scope.

## Layout

| Path | What |
|---|---|
| `src/main/kotlin/.../hsm/` | Signature-provider framework |
| `src/main/kotlin/.../hsm/alg/` | One `SignatureProviderFactory` per JOSE signing algorithm |
| `docker/` | NetHSM + Keycloak testbed |

## Build and test

```bash
./gradlew build          # compiles, tests, stages build/providers/
```

`build/providers/` holds the deployable set: the provider .jar file plus `kotlin-stdlib`.
Keycloak uses a single unrestricted classloader and gives `providers/` precedence over
its own libraries, so keep that directory minimal and keep every `org.keycloak:*`
dependency `compileOnly` — shading Keycloak classes into the jar is what produces
`ServiceConfigurationError: <Spi> not a subtype` at startup.

## Testing

```bash
./gradlew build
cd docker && docker compose up -d --build
./keycloak/register-provider.sh
```

This starts a factory-state NetHSM test container, provisions it, starts Keycloak with
the extension deployed, and registers a `nethsm` key provider on the master realm.

`register-provider.sh` is a separate step because the testbed runs `start-dev`, whose H2
database is in-memory: realm configuration is lost whenever the Keycloak container is
recreated, so re-run it after each `up --build`.

- Keycloak: <http://localhost:8080> (`admin` / `admin`)
- NetHSM API: <https://localhost:8443/api/v1> (self-signed cert)
- NetHSM operator: `keycloak` / `KeycloakKeycloak`

`docker/nethsm/provision.sh` generates one key per sign mode Keycloak needs:

| Key id | NetHSM type | Mechanism | For |
|---|---|---|---|
| `kc-rsa-pkcs1` | RSA 2048 | `RSA_Signature_PKCS1` | RS256/384/512 |
| `kc-rsa-pss` | RSA 2048 | `RSA_Signature_PSS_SHA*` | PS256/384/512 |
| `kc-ec-p256` | EC_P256 | `ECDSA_Signature` | ES256 |
| `kc-ed25519` | Curve25519 | `EdDSA_Signature` | EdDSA |

Tear down with `docker compose down`.

## License

Apache-2.0. See `LICENSE`.
