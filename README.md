# Keycloak Provider for NetHSM

A [Keycloak](https://www.keycloak.org/) key provider that natively integrates with
[Nitrokey NetHSM](https://www.nitrokey.com/products/nethsm) to perform key operations
(e.g. signing) while private keys never leave the HSM.

## Quality Warning

**This Keycloak provider has been developed and reviewed entirely by an AI. It has been tested successfully
by unit tests and integration tests. The code has not been reviewed by a human yet and therefore
use it at your own risk.**

## Features

- Signing of access tokens
- JCA provider to decrypt inbound JWE
- Ciphers: RSA 2048 (PKCS#1, PSS, OAEP), P256, P384, P521, Curve25519
- Supports multiple NetHSM in a round-robin fashion
- Uses Keycloak's SPI and NetHSM's REST API (without PKCS#11)

## Installation and Setup

Follow the [documentation](https://docs.nitrokey.com/nethsm/compatible/keycloak).

### Keycloak compatibility

| Extension | Keycloak |
|---|---|
| 0.1.x | 26.7.x |

The extension implements Keycloak SPIs that Keycloak itself marks internal and thus
could change over different versions.

## Configuration

Two layers. The connection and the Operator credential are server-wide, ops-owned and
secret; each realm only says which key IDs it claims.

### Server (`conf/keycloak.conf`, or `KC_SPI_KEYS__NETHSM__*`)

| Option | Default | Meaning |
|---|---|---|
| `spi-keys--nethsm--url` | — | API base including `/api/v1`. Comma-separated for a cluster; tried round-robin |
| `spi-keys--nethsm--username` | — | NetHSM user with the **Operator** role |
| `spi-keys--nethsm--passphrase` | — | User's passphrase |
| `spi-keys--nethsm--tls-fingerprints` | — | comma-separated SHA-256 certificate pins |
| `spi-keys--nethsm--tls-insecure` | `false` | disables verification; development only |
| `spi-keys--nethsm--timeout-seconds` | `10` | per request, once connected |
| `spi-keys--nethsm--connect-timeout-seconds` | `3` | to establish a connection; bounds how long an unreachable NetHSM holds a request thread |
| `spi-keys--nethsm--retries` | `2` | extra attempts per URL |
| `spi-keys--nethsm--retry-delay-ms` | `200` | between attempts |
| `spi-keys--nethsm--max-connections` | `20` | connection pool bound |
| `spi-keys--nethsm--discovery-cache-seconds` | `300` | how long discovered keys stay usable |
| `spi-keys--nethsm--discovery-max-stale-seconds` | `86400` | how long cached keys may keep being served once refreshes fail |
| `spi-keys--nethsm--on-unavailable` | `fail` | `fail` or `degrade` — see [Failure behaviour](#failure-behaviour) |

Omitting `url` leaves the provider registered but inert, so the JAR file is safe to ship in an
image that has no NetHSM.

An **Operator** credential is all this needs: the key operations Keycloak performs work
with it, and generating keys happens out of band. Nothing here checks the role, so keeping
Administrator out of the server configuration is least privilege to apply rather than a
guarantee this extension enforces.

Certificate pinning replaces hostname verification, because a pinned NetHSM certificate is usually
self-signed with a CN that does not match the address Keycloak uses. Get the fingerprint
with:

```bash
echo | openssl s_client -connect <HOST>:<PORT> 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout
```

Colons and case are ignored. A certificate that does not match is refused and the log
names the fingerprint it actually saw, which is the value to pin.

### Realm (*Realm Settings → Keys → Providers → nethsm*)

| Setting | Meaning |
|---|---|
| Key use | `sig` to sign tokens, `enc` to decrypt inbound JWE |
| Key ID prefix | every NetHSM key whose ID starts with this is published by this realm |
| Algorithm | which algorithm the keys are published under |
| Priority / Enabled / Active | standard Keycloak key provider settings |

One component means one algorithm, mirroring Keycloak's own providers. A NetHSM
`RSA_Signature_PKCS1` key is hash-agnostic and can serve RS256, RS384 or RS512.
A PSS key only appears under the algorithm its mechanism names. Keys that cannot serve
the chosen algorithm are skipped, so pointing a prefix at a mixed set is fine.

`kid` is the NetHSM key ID: stable across restarts and cluster nodes. Do not point two
components at the same key with different algorithms — they would publish two JWKS entries
under one `kid`.

## Algorithm mapping

Derived from each key's own `type` and `mechanisms`, so no algorithm is configured per
key — only the RS256/384/512 choice for a hash-agnostic PKCS1 key.

| Keycloak alg | NetHSM key type | `SignMode` | Note |
|---|---|---|---|
| RS256/384/512 | RSA | `PKCS1` | send the digest **prefixed with the DigestInfo header** |
| PS256/384/512 | RSA | `PSS_SHA256/384/512` | send the bare digest |
| ES256/384/512 | EC_P256/384/521 | `ECDSA` | returns ASN.1 DER; converted to fixed-width R‖S using Keycloak's own `ECDSAAlgorithm`, so HSM-backed and local EC keys are byte-identical |
| EdDSA | Curve25519 | `EdDSA` | send the **raw message**, not a digest — Ed25519 hashes internally and derives its nonce from that hash. Returns 64-byte r‖s, already JOSE-shaped |

### Key management (JWE)

Only the unwrap direction can involve the HSM. Encrypting *to* a client uses that
client's public key, so Keycloak never asks NetHSM to encrypt.

| Keycloak `alg` | NetHSM `DecryptMode` | Mechanism |
|---|---|---|
| `RSA-OAEP` | `OAEP_SHA1` | `RSA_Decryption_OAEP_SHA1` |
| `RSA-OAEP-256` | `OAEP_SHA256` | `RSA_Decryption_OAEP_SHA256` |

NetHSM's API names only the digest and documents nothing about the mask generation
function. Measured behaviour is that MGF1 uses the same digest, which is what JOSE
requires; `NetHsmContractIT` pins this in both directions so a firmware change cannot
break `RSA-OAEP-256` silently.

A decrypt failure is reported without a reason. The ciphertext arrives from
unauthenticated callers, so distinguishing a padding failure from any other failure would
turn this into a usable RSA decryption oracle.

#### Availability

Accepting encrypted request objects lets any caller drive HSM operations before
authenticating. NetHSM is shared with token signing, so a flood of decrypts competes with
it; `max-connections` bounds how much of the HSM this extension will consume at once, but
it is a ceiling, not fairness between decrypting and signing. Do not enable request-object
encryption on a client unless it is needed, and rate-limit the authorization endpoint at
the proxy if it is exposed publicly.

### SAML

SAML signs through XML-DSig rather than Keycloak's signature SPI, so it is served by this
extension's JCA provider (`DSA_SHA1` excepted — NetHSM has no DSA key type):

| Keycloak SAML algorithm | JCA name | NetHSM `SignMode` |
|---|---|---|
| `RSA_SHA1`/`RSA_SHA256`/`RSA_SHA512` | `SHA1/256/512withRSA` | `PKCS1` |
| `RSA_SHA256_MGF1`/`RSA_SHA512_MGF1` | `SHA256/512withRSAandMGF1` | `PSS_SHA256/512` |

A SAML signature identifies its key by X.509 certificate, not by public key alone.
Keycloak embeds that certificate in every document it signs and publishes it in the
realm's SAML descriptor, which is where a service provider gets the key it will trust.
NetHSM never creates certificates, so one has to be uploaded per signing key, out of band:

1. Ask NetHSM for a CSR for the key
2. Have your CA sign it
3. Store the resulting certificate in the NetHSM

### Verified

Verified end to end against a NetHSM container, each token checked with an independent
library against the realm JWKS: RS256, RS384, PS256, ES256, ES384, ES512, EdDSA.
RS512, PS384 and PS512 share a code path with a verified sibling and differ only by a
hash constant, which is covered by unit tests.

For SAML, every registered JCA algorithm is signed in the HSM and verified locally, and a
document is signed and validated through `XMLSignatureFactory` — the same API Keycloak's
`XMLSignatureUtil` drives. That exercises the mechanism SAML uses, but **not** a real
service provider; an end-to-end run against an SP is still outstanding.

## Key rotation

Keycloak signs with the **first** key a provider yields, and this extension orders
discovered keys by ID. A component matching several keys is therefore not a rotation
mechanism: adding a second key under a shared prefix publishes it, but signing stays with
whichever ID sorts first. The provider logs a warning when an active signing component
matches more than one key, naming the one that will sign.

Rotate with **one component per key generation** instead:

1. Generate the new key in NetHSM under a new ID, e.g. `kc-rsa-2026b` alongside
   `kc-rsa-2026a`. This is done by interacting with NetHSM directly, outside of Keycloak.
2. Add a second `nethsm` component for the new ID at a **higher priority**, active. It
   takes over signing immediately, and the new `kid` appears in the JWKS at the same time.
3. Flip the old component to **passive** — *Active* off, *Enabled* on. Its key stays in
   the JWKS, so tokens signed before the cutover keep verifying, but it no longer signs.
4. Once every token signed by the old key has expired, disable or delete the old
   component, and only then remove the key from NetHSM.

Two timing details worth planning around:

- A key generated in NetHSM does not appear until the discovery cache expires, up to
  `discovery-cache-seconds` (default 300).
- Relying parties cache the JWKS. Step 3 is what stops that mattering: the old key is
  still published, so a client that has not re-fetched can still verify. Do not merge
  steps 2 and 4 into one change.

Because `kid` is the NetHSM key ID, it changes at step 2, which is the signal for a
relying party to re-fetch. Reusing an ID for a new key would defeat that, so generate a
new ID rather than replacing a key in place.

## Failure behaviour

An unreachable NetHSM must not quietly become "this realm has no keys", because that is
not a neutral state. `DefaultKeyManager` reacts to a realm with no active key by asking
the generated key provider factories for a fallback — it logs *"No keys found for
realm={0} and algorithm={1} for use={2}. Generating keys."* — and Keycloak then carries
on issuing tokens signed by a **software** key that never went near the HSM.

So the provider fails closed by default, in three layers:

| Situation | Behaviour |
|---|---|
| NetHSM unreachable, keys previously discovered | serves cached metadata; signing then fails per request |
| NetHSM unreachable mid-refresh (the key list arrived, the keys did not) | treated as a failed discovery, not as "this prefix matches nothing" |
| cached keys older than `discovery-max-stale-seconds` | discarded, then handled as if nothing were cached |
| NetHSM unreachable, nothing cached (cold start) | `on-unavailable=fail` (default): propagates the error, so no fallback key is generated |
| | `on-unavailable=degrade`: contributes no keys and lets Keycloak generate a software key |

Failing closed has an operational edge worth planning for. **If a realm's default
signature algorithm is served by NetHSM keys and NetHSM goes away, nobody can obtain an
admin token for that realm either** — including you, to fix it. Recovery is through
server configuration rather than the admin API: set
`spi-keys--nethsm--on-unavailable=degrade` and restart, or disable the component. Keeping
the `master` realm on non-HSM keys avoids the situation entirely.

## Disabling software keys

In case of a misconfigured key prefix that matches nothing the discovery would succeed and
return an empty set. This provider contributes no keys, and Keycloak signs with the
`rsa-generated` software key that every realm has by default. Similarly, for encryption
`rsa-enc-generated` is present by default. Therefore it is recommended to remove the
generated providers so that in case of no usable HSM key it would error instead of quietly
substituting one:

```
spi-keys--rsa-generated--enabled=false
spi-keys--ec-generated--enabled=false
spi-keys--rsa-enc-generated--enabled=false
```

Alternatively delete those providers from the realm, and check the published `kid` after
any key change: it should be the NetHSM key ID.

## Known limitations

- Unsupported ciphers: `HS256`, `HS384`, `HS512`, `ECDH-ES`, `ECDH-ES+A128KW`, `+A192KW`,
  `+A256KW`, `RSA1_5` (deliberately excluded to avoid Bleichenbacher oracle attacks),
  `A128KW`, `A192KW`, `A256KW`, `ML-DSA-44/65/87`, Brainpool curves, `EC_P256K1`, `DSA`
  `HS*` (symmetric keys are out of scope)
- OID4VC credential issuance will not use the HSM.

## Layout

| Path | What |
|---|---|
| `src/main/kotlin/.../hsm/` | Signature-provider picking framework |
| `src/main/kotlin/.../hsm/alg/` | One `SignatureProviderFactory` per JOSE signing algorithm |
| `src/main/kotlin/.../client/` | NetHSM REST client, discovery and caching |
| `src/main/kotlin/.../jca/` | JCA provider making an HSM-held key usable for RSA-OAEP decryption |
| `docker/` | NetHSM + Keycloak testbed |

## Build and test

```bash
./gradlew build              # compiles, unit tests, stages build/providers/
./gradlew integrationTest    # brings the testbed up, runs end-to-end tests, tears it down
```

Three layers, and the distinction matters:

| | Subject | Needs Docker |
|---|---|---|
| `src/test` | algorithm derivation, signature conversion, the fail-closed branches | no |
| `src/integrationTest/…IT` | **Keycloak** — its token, JWKS and admin endpoints | yes |
| `NetHsmContractIT` | **NetHSM** — the one assumption the RSA path rests on | yes |

The end-to-end tests ask Keycloak for a token and check that it carries the NetHSM `kid`
and verifies against the realm's published JWKS, which is exactly what a relying party
does. NetHSM is a fixture the compose stack provides.

The exception is `NetHsmContractIT`, which pins the one NetHSM behaviour everything else
assumes: that `PKCS1` mode signs submitted bytes verbatim, so a DigestInfo-prefixed
digest yields an EMSA-PKCS1-v1_5 signature. If firmware ever changed that, this fails
with an obvious cause instead of every RS\* case failing in a way that looks like our bug.

`integrationTest` is not part of `check`, because each run includes time-consuming image
build and `kc.sh build`.

If you run Gradle itself inside a container against the host's Docker daemon, mount the
project at its real host path. Compose resolves bind mounts on the daemon side, so a
mismatch makes `provision.sh` mount as an empty directory, the provision step exit 0
having done nothing, and every test then find an unprovisioned NetHSM.

`build/providers/` holds a user-deployable JAR file.

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

`docker/nethsm/provision.sh` generates one key per NetHSM mode Keycloak needs:

| Key ID | NetHSM type | Mechanism | For |
|---|---|---|---|
| `kc-rsa-pkcs1` | RSA 2048 | `RSA_Signature_PKCS1` | RS256/384/512 |
| `kc-rsa-pss` | RSA 2048 | `RSA_Signature_PSS_SHA*` | PS256/384/512 |
| `kc-rsa-oaep` | RSA 2048 | `RSA_Decryption_OAEP_SHA1/SHA256` | RSA-OAEP, RSA-OAEP-256 |
| `kc-ec-p256` | EC_P256 | `ECDSA_Signature` | ES256 |
| `kc-ec-p384` | EC_P384 | `ECDSA_Signature` | ES384 |
| `kc-ec-p521` | EC_P521 | `ECDSA_Signature` | ES512 |
| `kc-ed25519` | Curve25519 | `EdDSA_Signature` | EdDSA |

These are named by mechanism because they exist to exercise algorithms; `kc-rot-2026a`
and `kc-rot-2026b` show the generation naming that [rotation](#key-rotation) wants.

`register-provider.sh` defaults to RS256; override to register any other algorithm:

```bash
NAME=nethsm-es256 KEY_PREFIX=kc-ec-p256  ALGORITHM=ES256 ./keycloak/register-provider.sh
NAME=nethsm-eddsa KEY_PREFIX=kc-ed25519  ALGORITHM=EdDSA ./keycloak/register-provider.sh
```

The script registers signing keys. An encryption key needs `keyUse` set to `enc`, which
is a component setting rather than a script option — configure it in the admin console.

Tear down with `docker compose down`.

## License

Apache-2.0. See `LICENSE`.
