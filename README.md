# Keycloak Provider for NetHSM

A Keycloak key provider that natively integrates with [Nitrokey NetHSM](https://www.nitrokey.com/products/nethsm)
to perform key operations (e.g. signing) while private keys never leave the HSM.

Status: **signing and JWE decryption both working end to end.** Keycloak access
tokens signed inside the HSM verify against the realm's published JWKS for RSA, ECDSA and
Ed25519, and an encrypted request object is decrypted with an HSM-held RSA key. The
connection is pooled and certificate-pinned, and an unreachable NetHSM fails closed
rather than letting Keycloak fall back to a software key.

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
| `spi-keys--nethsm--on-unavailable` | `fail` | `fail` or `degrade` — see [Failure behaviour](#failure-behaviour) |

Omitting `url` leaves the provider registered but inert, so the jar is safe to ship in an
image that has no NetHSM.

An **Operator** credential is all this needs: the key operations Keycloak performs work
with it, and generating keys happens out of band. Nothing here checks the role, so keeping
Administrator out of the server configuration is least privilege to apply rather than a
guarantee this extension enforces.

Pinning replaces hostname verification, because a pinned NetHSM certificate is usually
self-signed with a CN that does not match the address Keycloak uses. Get the fingerprint
with:

```bash
echo | openssl s_client -connect nethsm:8443 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout
```

Colons and case are ignored. A certificate that does not match is refused and the log
names the fingerprint it actually saw, which is the value to pin.

### Realm (*Realm Settings → Keys → Providers → nethsm*)

| Setting | Meaning |
|---|---|
| Key use | `sig` to sign tokens, `enc` to decrypt inbound JWE |
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

#### Why this goes through JCA rather than a Keycloak SPI

Keycloak consults its `CekManagementProvider` SPI only when it *encrypts*. Inbound JWE is
decrypted by `DefaultRsaKeyEncryptionJWEAlgorithmProvider`, which does a plain
`Cipher.getInstance(transformation).init(DECRYPT_MODE, key)` — the SPI is never asked. An
earlier attempt to shadow that SPI registered correctly and won its slot, and still never
ran on the path that mattered.

So the extension registers a JCA provider instead. JCA defers `Cipher` provider selection
until `init` and skips providers that reject the key, so one that accepts the opaque
NetHSM key handle is chosen with no change to Keycloak. It is appended last and declares
`SupportedKeyClasses`, so ordinary RSA keys never reach it and keep using the platform
implementation. PKCS#1 v1.5 padding is refused, for the reason above.

### Verified

Verified end to end against a real NetHSM, each token checked with an independent
library against the realm JWKS: RS256, RS384, PS256, ES256, ES384, ES512, EdDSA.
RS512, PS384 and PS512 share a code path with a verified sibling and differ only by a
hash constant, which is covered by unit tests.

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
| NetHSM unreachable, nothing cached (cold start) | `on-unavailable=fail` (default): propagates the error, so no fallback key is generated |
| | `on-unavailable=degrade`: contributes no keys and lets Keycloak generate a software key |

Verified: with NetHSM stopped and a cold cache, the realm keys endpoint returns 500, the
log says `nothing is cached; failing closed`, and **no software key is generated**.

Failing closed has an operational edge worth planning for. **If a realm's default
signature algorithm is served by NetHSM keys and NetHSM goes away, nobody can obtain an
admin token for that realm either** — including you, to fix it. Recovery is through
server configuration rather than the admin API: set
`spi-keys--nethsm--on-unavailable=degrade` and restart, or disable the component. Keeping
the `master` realm on non-HSM keys avoids the situation entirely.

As defence in depth, the fallback can be removed altogether by disabling the generated
key providers, so that a realm with no HSM keys errors instead of inventing one:

```
spi-keys--rsa-generated--enabled=false
spi-keys--ec-generated--enabled=false
```

## Disabling software keys

Keycloak offers algorithms that a NetHSM-backed key cannot serve. A realm can still use
them, but only with Keycloak's own software keys — this extension will not publish a key
under any of them.

| Algorithm | Why not |
|---|---|
| `HS256` / `HS384` / `HS512` | HMAC over a shared secret. NetHSM stores AES keys but exposes no HMAC operation, and a symmetric realm key has no HSM story worth having. |
| `ECDH-ES`, `ECDH-ES+A128KW`, `+A192KW`, `+A256KW` | Require an ECDH key-agreement (derive) operation. NetHSM has none, so these can never be HSM-backed. |
| `RSA1_5` | NetHSM could do it (`RSA_Decryption_PKCS1`), but it is deliberately excluded: PKCS#1 v1.5 decryption of attacker-supplied ciphertext is the classic Bleichenbacher oracle, and the ciphertext here arrives from unauthenticated callers. |
| `A128KW`, `A192KW`, `A256KW` | Symmetric key wrapping. Same reason as `HS*`. |
| `ML-DSA-44/65/87` | Post-quantum signatures. No NetHSM mechanism. |
| Brainpool curves, `EC_P256K1` | NetHSM supports these key types, but JOSE defines no `alg` for them. |

NetHSM's `BIP340_Signature` (Schnorr) and its AES-CBC encrypt/decrypt likewise have no
JOSE equivalent and are out of scope.

## Known limitations

- **OID4VC credential issuance will not use the HSM.** `KeyWrapper.cloneKey()` hardcodes
  `new KeyWrapper()` and so erases the `HsmKeyWrapper` subtype that dispatch relies on.
  In Keycloak 26.7.3 its only caller is
  `org.keycloak.protocol.oid4vc.issuance.signing.AbstractCredentialSigner`; OIDC and SAML
  are unaffected.
- **`HS*` algorithms are not registered** — symmetric keys are out of scope.

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

The end-to-end tests are not tests *of* NetHSM. They ask Keycloak for a token and check
that it carries the NetHSM `kid` and verifies against the realm's published JWKS, which
is exactly what a relying party does. NetHSM is a fixture the compose stack provides.

The exception is `NetHsmContractIT`, which pins the one NetHSM behaviour everything else
assumes: that `PKCS1` mode signs submitted bytes verbatim, so a DigestInfo-prefixed
digest yields an EMSA-PKCS1-v1_5 signature. If firmware ever changed that, this fails
with an obvious cause instead of every RS\* case failing in a way that looks like our bug.

`integrationTest` is not part of `check`, because each run pays for an image build and
`kc.sh build`. It is also never up to date: what it exercises lives in containers Gradle
cannot see, so unchanged sources say nothing about whether it would still pass.

If you run Gradle itself inside a container against the host's Docker daemon, mount the
project at its real host path. Compose resolves bind mounts on the daemon side, so a
mismatch makes `provision.sh` mount as an empty directory, the provision step exit 0
having done nothing, and every test then find an unprovisioned NetHSM.

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

`docker/nethsm/provision.sh` generates one key per NetHSM mode Keycloak needs:

| Key id | NetHSM type | Mechanism | For |
|---|---|---|---|
| `kc-rsa-pkcs1` | RSA 2048 | `RSA_Signature_PKCS1` | RS256/384/512 |
| `kc-rsa-pss` | RSA 2048 | `RSA_Signature_PSS_SHA*` | PS256/384/512 |
| `kc-rsa-oaep` | RSA 2048 | `RSA_Decryption_OAEP_SHA1/SHA256` | RSA-OAEP, RSA-OAEP-256 |
| `kc-ec-p256` | EC_P256 | `ECDSA_Signature` | ES256 |
| `kc-ec-p384` | EC_P384 | `ECDSA_Signature` | ES384 |
| `kc-ec-p521` | EC_P521 | `ECDSA_Signature` | ES512 |
| `kc-ed25519` | Curve25519 | `EdDSA_Signature` | EdDSA |

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
