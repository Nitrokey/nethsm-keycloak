# Keycloak Provider for NetHSM

A Keycloak key provider that signs tokens with a [Nitrokey NetHSM](https://www.nitrokey.com/products/nethsm),
talking to the NetHSM REST API directly. Private keys never leave the HSM.

Status: **scaffold and testbed.** The signature-provider framework is in place and
verified end to end; the NetHSM key provider itself comes next.

## Quality Warning

**This project has been developed and reviewed entirely by an AI. It has been tested successfully
by unit tests and integration tests. The code has not been reviewed by a human yet and therefore
use it at your own risk.**

## Algorithm mapping

| Keycloak alg | NetHSM key type | `SignMode` | Note |
|---|---|---|---|
| RS256/384/512 | RSA | `PKCS1` | send the digest **prefixed with the DigestInfo header** |
| PS256/384/512 | RSA | `PSS_SHA256/384/512` | send the bare digest |
| ES256/384/512 | EC_P256/384/521 | `ECDSA` | returns ASN.1 DER; JOSE needs fixed-width R‖S |
| EdDSA | Curve25519 | `EdDSA` | send the raw message; returns 64-byte r‖s, already JOSE-shaped |

## Known limitations

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
| `src/main/kotlin/.../hsm/` | Signature-provider framework, derived from [keycloak-hsm](https://github.com/denniskniep/keycloak-hsm) (Apache-2.0), translated to Kotlin and updated for Keycloak 26.x |
| `src/main/kotlin/.../hsm/alg/` | One `SignatureProviderFactory` per JOSE signing algorithm |
| `docker/` | NetHSM + Keycloak testbed |

The framework is vendored rather than depended on. It is ~200 lines, upstream targets
Keycloak 22.0.1, and the SPI has since changed in ways that break it outright: Keycloak
added an abstract `SignatureProviderFactory.getJwkPrivateKeyClaims()` after 22.x, which
upstream does not implement.

## Build and test

```bash
./gradlew build          # compiles, tests, stages build/providers/
```

`build/providers/` holds the deployable set: the provider jar plus `kotlin-stdlib`.
Keycloak uses a single unrestricted classloader and gives `providers/` precedence over
its own libraries, so keep that directory minimal and keep every `org.keycloak:*`
dependency `compileOnly` — shading Keycloak classes into the jar is what produces
`ServiceConfigurationError: <Spi> not a subtype` at startup.

## Testing

```bash
./gradlew build
cd docker && docker compose up -d --build
```

This starts a factory-state NetHSM (`nitrokey/nethsm:testing-v5.0`), provisions it, and
starts Keycloak with the extension deployed.

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

`testing-v5.0` is pinned deliberately: RSA PKCS1 sign mechanisms — what RS256 needs —
are not usable on NetHSM v3.0.

Tear down with `docker compose down`.

## License

Apache-2.0. See `LICENSE`.
