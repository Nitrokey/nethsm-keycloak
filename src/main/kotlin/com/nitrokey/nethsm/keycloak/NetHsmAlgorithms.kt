package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmKey
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.ECDSAAlgorithm

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
    private const val MECH_ECDSA = "ECDSA_Signature"
    private const val MECH_EDDSA = "EdDSA_Signature"

    /** NetHSM `SignMode` values. */
    private const val MODE_PKCS1 = "PKCS1"
    private const val MODE_ECDSA = "ECDSA"
    private const val MODE_EDDSA = "EdDSA"

    private val PSS_MECHANISM_TO_ALGORITHM = mapOf(
        "RSA_Signature_PSS_SHA256" to Algorithm.PS256,
        "RSA_Signature_PSS_SHA384" to Algorithm.PS384,
        "RSA_Signature_PSS_SHA512" to Algorithm.PS512,
    )

    private val PKCS1_ALGORITHMS = setOf(Algorithm.RS256, Algorithm.RS384, Algorithm.RS512)

    /** NetHSM key type to the single JOSE algorithm that curve implies. */
    private val EC_TYPE_TO_ALGORITHM = mapOf(
        "EC_P256" to Algorithm.ES256,
        "EC_P384" to Algorithm.ES384,
        "EC_P521" to Algorithm.ES512,
    )

    /** The `crv` a JWK for this key type carries. */
    private val TYPE_TO_CURVE = mapOf(
        "EC_P256" to "P-256",
        "EC_P384" to "P-384",
        "EC_P521" to "P-521",
        "Curve25519" to Algorithm.Ed25519,
    )

    private val SIGN_MODES = mapOf(
        Algorithm.RS256 to MODE_PKCS1,
        Algorithm.RS384 to MODE_PKCS1,
        Algorithm.RS512 to MODE_PKCS1,
        Algorithm.PS256 to "PSS_SHA256",
        Algorithm.PS384 to "PSS_SHA384",
        Algorithm.PS512 to "PSS_SHA512",
        Algorithm.ES256 to MODE_ECDSA,
        Algorithm.ES384 to MODE_ECDSA,
        Algorithm.ES512 to MODE_ECDSA,
        Algorithm.EdDSA to MODE_EDDSA,
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

    private val ECDSA_ALGORITHMS = setOf(Algorithm.ES256, Algorithm.ES384, Algorithm.ES512)

    /**
     * Keycloak algorithms this key can sign with, given its type and enabled mechanisms.
     * Empty means the key is not usable for JWS signing and discovery should skip it.
     */
    fun supportedAlgorithms(key: NetHsmKey): Set<String> = when {
        key.type == "RSA" -> {
            val fromPkcs1 = if (MECH_PKCS1 in key.mechanisms) PKCS1_ALGORITHMS else emptySet()
            fromPkcs1 + key.mechanisms.mapNotNull { PSS_MECHANISM_TO_ALGORITHM[it] }
        }
        key.type == "Curve25519" ->
            if (MECH_EDDSA in key.mechanisms) setOf(Algorithm.EdDSA) else emptySet()
        key.type in EC_TYPE_TO_ALGORITHM ->
            if (MECH_ECDSA in key.mechanisms) setOf(EC_TYPE_TO_ALGORITHM.getValue(key.type)) else emptySet()
        else -> emptySet()
    }

    /** The JCA algorithm name for a NetHSM key type, used to label opaque key handles. */
    fun jcaAlgorithmFor(type: String): String = when {
        type == "RSA" -> "RSA"
        type == "Curve25519" -> Algorithm.Ed25519
        type in EC_TYPE_TO_ALGORITHM -> "EC"
        else -> throw UnsupportedOperationException("no JCA algorithm for NetHSM key type $type")
    }

    /** The `crv` for a NetHSM key type, or null for RSA. */
    fun curveFor(type: String): String? = TYPE_TO_CURVE[type]

    /** The NetHSM `SignMode` for a Keycloak algorithm. */
    fun signMode(algorithm: String): String =
        SIGN_MODES[algorithm] ?: throw UnsupportedOperationException("no NetHSM sign mode for $algorithm")

    /**
     * True when NetHSM wants the message rather than a digest. Ed25519 hashes internally
     * and derives its nonce from that hash, so pre-hashing here would produce a
     * signature over the wrong value.
     */
    fun signsRawMessage(algorithm: String): Boolean = algorithm == Algorithm.EdDSA

    /**
     * The prefix to prepend to the digest before signing, or null when the mode derives
     * the hash itself (`PSS_*`) or takes a bare digest (`ECDSA`).
     *
     * Copied, because [DIGEST_INFO] holds process-wide constants and a ByteArray is
     * mutable: handing out the original would let one careless caller corrupt the RFC 8017
     * header every later signature is built from.
     */
    fun digestInfoPrefix(algorithm: String): ByteArray? = DIGEST_INFO[algorithm]?.copyOf()

    /**
     * Converts a NetHSM signature into what JOSE expects.
     *
     * `ECDSA` mode returns an ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`, while JWS
     * needs r and s concatenated at fixed width; the conversion is Keycloak's own, so
     * HSM-backed and local EC keys produce byte-identical output. `EdDSA` mode already
     * returns RFC 8032 r||s, and RSA signatures need nothing.
     */
    fun toJoseSignature(algorithm: String, signature: ByteArray): ByteArray =
        if (algorithm in ECDSA_ALGORITHMS) {
            ECDSAAlgorithm.asn1derToConcatenatedRS(signature, ECDSAAlgorithm.getSignatureLength(algorithm))
        } else {
            signature
        }

    private fun String.hexToByteArray(): ByteArray =
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
