package com.nitrokey.nethsm.keycloak

import java.security.PrivateKey

/**
 * An opaque reference to a private key that lives inside NetHSM.
 *
 * Carries no key material -- `getEncoded()` and `getFormat()` return null, which is how
 * the JCA models a non-extractable key and what PKCS#11 providers hand back.
 *
 * It exists because Keycloak's encryption SPI, unlike its signature SPI, never sees the
 * `KeyWrapper`: `JWEAlgorithmProvider.decodeCek` is handed a bare `java.security.Key`.
 * Keycloak reaches that key through `KeyWrapper.getPrivateKey()`, so returning this
 * handle is what lets [com.nitrokey.nethsm.keycloak.jca.NetHsmCipherSpi] recognise a
 * NetHSM key and route the unwrap to the HSM instead of trying to use material it does
 * not have.
 */
class NetHsmPrivateKeyHandle(
    val keyId: String,
    private val jcaAlgorithm: String,
) : PrivateKey {

    override fun getAlgorithm(): String = jcaAlgorithm

    /** Null: there is no encoding, because the key cannot leave the HSM. */
    override fun getFormat(): String? = null

    /** Null for the same reason. Callers that need material will fail loudly rather than silently use a placeholder. */
    override fun getEncoded(): ByteArray? = null

    override fun toString(): String = "NetHsmPrivateKeyHandle(keyId=$keyId, algorithm=$jcaAlgorithm)"

    private companion object {
        private const val serialVersionUID: Long = 1L
    }
}
