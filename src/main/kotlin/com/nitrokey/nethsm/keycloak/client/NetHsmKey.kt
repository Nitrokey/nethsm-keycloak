package com.nitrokey.nethsm.keycloak.client

import com.fasterxml.jackson.databind.JsonNode
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Key metadata as returned by `GET /keys/{id}`.
 *
 * Everything Keycloak needs to build a `KeyWrapper` is in that one response -- type,
 * mechanisms and the public key -- so discovery costs one list call plus one call per
 * key, and no algorithm has to be configured by hand.
 */
class NetHsmKey(
    val id: String,
    /** `RSA`, `EC_P256`, `EC_P384`, `EC_P521`, `Curve25519`, ... */
    val type: String,
    /** e.g. `RSA_Signature_PKCS1`, `ECDSA_Signature`, `EdDSA_Signature`. */
    val mechanisms: Set<String>,
    val publicKey: PublicKey,
) {
    companion object {
        /** NetHSM curve names to the JDK's names for the same curves. */
        private val EC_CURVES = mapOf(
            "EC_P256" to "secp256r1",
            "EC_P384" to "secp384r1",
            "EC_P521" to "secp521r1",
        )

        /**
         * SubjectPublicKeyInfo header for an Ed25519 key: SEQUENCE { SEQUENCE { OID
         * 1.3.101.112 }, BIT STRING }. Prepending it turns NetHSM's raw 32-byte key into
         * something `X509EncodedKeySpec` accepts, which is far less fiddly than
         * reconstructing an `EdECPoint` from the little-endian encoding by hand.
         */
        private val ED25519_SPKI_PREFIX = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )

        /**
         * Parses a `GET /keys/{id}` body. Returns null for key types this extension
         * cannot represent, so one unsupported key inside a realm's prefix does not
         * break discovery for the rest. NetHSM also offers EC_P256K1 and the Brainpool
         * curves, which have no JOSE algorithm.
         */
        fun parse(id: String, node: JsonNode): NetHsmKey? {
            val type = node.path("type").asText(null) ?: return null
            val mechanisms = node.path("mechanisms").mapNotNull { it.asText(null) }.toSet()
            val public = node.path("public")

            val publicKey = when {
                type == "RSA" -> rsaPublicKey(public)
                type == "Curve25519" -> ed25519PublicKey(public)
                type in EC_CURVES -> ecPublicKey(public, EC_CURVES.getValue(type))
                else -> null
            } ?: return null

            return NetHsmKey(id, type, mechanisms, publicKey)
        }

        /**
         * NetHSM returns the modulus and exponent as big-endian base64. Reading them
         * here avoids a second round trip to `/keys/{id}/public.pem`.
         */
        private fun rsaPublicKey(public: JsonNode): PublicKey? {
            val modulus = public.path("modulus").asText(null) ?: return null
            val exponent = public.path("publicExponent").asText(null) ?: return null
            val decoder = Base64.getDecoder()
            val spec = RSAPublicKeySpec(
                BigInteger(1, decoder.decode(modulus)),
                BigInteger(1, decoder.decode(exponent)),
            )
            return KeyFactory.getInstance("RSA").generatePublic(spec)
        }

        /** `public.data` is the uncompressed point: `0x04 || X || Y`. */
        private fun ecPublicKey(public: JsonNode, jdkCurve: String): PublicKey? {
            val data = public.path("data").asText(null) ?: return null
            val point = Base64.getDecoder().decode(data)
            if (point.size < 3 || point[0] != 0x04.toByte() || point.size % 2 == 0) return null

            val fieldSize = (point.size - 1) / 2
            val spec = ECPublicKeySpec(
                ECPoint(
                    BigInteger(1, point.copyOfRange(1, 1 + fieldSize)),
                    BigInteger(1, point.copyOfRange(1 + fieldSize, point.size)),
                ),
                curveParameters(jdkCurve),
            )
            return KeyFactory.getInstance("EC").generatePublic(spec)
        }

        private fun curveParameters(jdkCurve: String): ECParameterSpec =
            AlgorithmParameters.getInstance("EC")
                .apply { init(ECGenParameterSpec(jdkCurve)) }
                .getParameterSpec(ECParameterSpec::class.java)

        /** `public.data` is the raw 32-byte Ed25519 public key. */
        private fun ed25519PublicKey(public: JsonNode): PublicKey? {
            val data = public.path("data").asText(null) ?: return null
            val raw = Base64.getDecoder().decode(data)
            if (raw.size != 32) return null
            return KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(ED25519_SPKI_PREFIX + raw))
        }
    }
}
