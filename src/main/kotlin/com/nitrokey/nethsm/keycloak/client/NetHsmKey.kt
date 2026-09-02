package com.nitrokey.nethsm.keycloak.client

import com.fasterxml.jackson.databind.JsonNode
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec
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
        /**
         * Parses a `GET /keys/{id}` body. Returns null for key types this extension
         * cannot represent yet, so one unsupported key in a realm's prefix does not
         * break discovery for the rest.
         */
        fun parse(id: String, node: JsonNode): NetHsmKey? {
            val type = node.path("type").asText(null) ?: return null
            val mechanisms = node.path("mechanisms").mapNotNull { it.asText(null) }.toSet()
            val public = node.path("public")

            val publicKey = when (type) {
                "RSA" -> rsaPublicKey(public) ?: return null
                else -> return null // EC and Curve25519 are added separately
            }
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
    }
}
