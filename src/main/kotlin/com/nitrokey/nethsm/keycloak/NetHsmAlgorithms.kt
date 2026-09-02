package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmKey
import org.keycloak.crypto.Algorithm

/**
 * Derives what a NetHSM key can be used for from its own metadata, so no algorithm has
 * to be configured per key.
 *
 * The mapping is one-to-one except for `RSA_Signature_PKCS1`, which is hash-agnostic --
 * NetHSM signs whatever DigestInfo-prefixed value it is handed, so a single PKCS1 key
 * serves RS256, RS384 and RS512 equally. That is the one case a realm has to choose,
 * and the provider's `algorithm` setting is that choice.
 */
object NetHsmAlgorithms {

    private const val MECH_PKCS1 = "RSA_Signature_PKCS1"

    /** NetHSM `SignMode` values. */
    private const val MODE_PKCS1 = "PKCS1"

    private val PSS_MECHANISM_TO_ALGORITHM = mapOf(
        "RSA_Signature_PSS_SHA256" to Algorithm.PS256,
        "RSA_Signature_PSS_SHA384" to Algorithm.PS384,
        "RSA_Signature_PSS_SHA512" to Algorithm.PS512,
    )

    private val PKCS1_ALGORITHMS = setOf(Algorithm.RS256, Algorithm.RS384, Algorithm.RS512)

    private val SIGN_MODES = mapOf(
        Algorithm.RS256 to MODE_PKCS1,
        Algorithm.RS384 to MODE_PKCS1,
        Algorithm.RS512 to MODE_PKCS1,
        Algorithm.PS256 to "PSS_SHA256",
        Algorithm.PS384 to "PSS_SHA384",
        Algorithm.PS512 to "PSS_SHA512",
    )

    /**
     * The DigestInfo headers from RFC 8017 A.2.4. NetHSM's `PKCS1` mode signs the value
     * verbatim, so producing an EMSA-PKCS1-v1_5 signature means prefixing the digest
     * ourselves -- exactly what the API documentation asks for.
     */
    private val DIGEST_INFO = mapOf(
        Algorithm.RS256 to "3031300d060960864801650304020105000420".hexToByteArray(),
        Algorithm.RS384 to "3041300d060960864801650304020205000430".hexToByteArray(),
        Algorithm.RS512 to "3051300d060960864801650304020305000440".hexToByteArray(),
    )

    /**
     * Keycloak algorithms this key can sign with, given its type and enabled mechanisms.
     * Empty means the key is not usable for JWS signing and discovery should skip it.
     */
    fun supportedAlgorithms(key: NetHsmKey): Set<String> {
        if (key.type != "RSA") return emptySet() // EC and Curve25519 are added separately
        val fromPss = key.mechanisms.mapNotNull { PSS_MECHANISM_TO_ALGORITHM[it] }
        val fromPkcs1 = if (MECH_PKCS1 in key.mechanisms) PKCS1_ALGORITHMS else emptySet()
        return fromPkcs1 + fromPss
    }

    /** The NetHSM `SignMode` for a Keycloak algorithm. */
    fun signMode(algorithm: String): String =
        SIGN_MODES[algorithm] ?: throw UnsupportedOperationException("no NetHSM sign mode for $algorithm")

    /**
     * The prefix to prepend to the digest before signing, or null when the mode expects
     * a bare digest (`PSS_*`).
     *
     * Copied, because [DIGEST_INFO] holds process-wide constants and a ByteArray is
     * mutable: handing out the original would let one careless caller corrupt the RFC 8017
     * header every later signature is built from.
     */
    fun digestInfoPrefix(algorithm: String): ByteArray? = DIGEST_INFO[algorithm]?.copyOf()

    private fun String.hexToByteArray(): ByteArray =
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
