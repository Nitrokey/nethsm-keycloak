package com.nitrokey.nethsm.keycloak.support

import com.fasterxml.jackson.databind.JsonNode
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.crypto.ECDSAAlgorithm
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Verifies a compact JWS against a JWK from Keycloak's JWKS endpoint.
 *
 * Deliberately independent of the extension's own signing path: it reconstructs the
 * public key from what Keycloak publishes and verifies with the JDK, so a test passing
 * means a normal relying party would accept the token.
 */
object Jws {

    init {
        // ECDSAAlgorithm's DER converters resolve a CryptoProvider through
        // CryptoIntegration, which a running Keycloak sets up during startup but a test
        // JVM does not. Without this, only the ES* cases fail, with an error that looks
        // like it came from the extension rather than from this helper.
        if (!CryptoIntegration.isInitialised()) {
            CryptoIntegration.init(Jws::class.java.classLoader)
        }
    }

    private val decoder = Base64.getUrlDecoder()

    fun decodeHeader(token: String): JsonNode =
        Json.read(b64(token.substringBefore('.')))

    /** Throws if the signature does not verify. */
    fun verify(token: String, jwk: JsonNode) {
        val (headerB64, payloadB64, signatureB64) = token.split('.').let {
            require(it.size == 3) { "not a compact JWS: $token" }
            Triple(it[0], it[1], it[2])
        }
        val signingInput = "$headerB64.$payloadB64".toByteArray()
        val signature = b64(signatureB64)
        val algorithm = Json.read(b64(headerB64)).path("alg").asText()

        val verifier = when {
            algorithm.startsWith("RS") -> Signature.getInstance("SHA${algorithm.drop(2)}withRSA")
            algorithm.startsWith("PS") -> pssVerifier(algorithm)
            algorithm.startsWith("ES") -> Signature.getInstance("SHA${algorithm.drop(2)}withECDSA")
            algorithm == "EdDSA" -> Signature.getInstance("Ed25519")
            else -> error("unsupported alg $algorithm")
        }

        // JWS carries ECDSA as fixed-width r||s; the JDK verifier wants ASN.1 DER.
        val forJdk = if (algorithm.startsWith("ES")) {
            ECDSAAlgorithm.concatenatedRSToASN1DER(signature, ECDSAAlgorithm.getSignatureLength(algorithm))
        } else {
            signature
        }

        verifier.initVerify(publicKey(jwk))
        verifier.update(signingInput)
        check(verifier.verify(forJdk)) { "$algorithm signature did not verify against the published JWK" }
    }

    private fun pssVerifier(algorithm: String): Signature {
        val hash = "SHA-${algorithm.drop(2)}"
        val digestLength = algorithm.drop(2).toInt() / 8
        return Signature.getInstance("RSASSA-PSS").apply {
            setParameter(PSSParameterSpec(hash, "MGF1", MGF1ParameterSpec(hash), digestLength, 1))
        }
    }

    private fun publicKey(jwk: JsonNode): PublicKey = when (val kty = jwk.path("kty").asText()) {
        "RSA" -> KeyFactory.getInstance("RSA").generatePublic(
            RSAPublicKeySpec(int(jwk, "n"), int(jwk, "e")),
        )

        "EC" -> {
            val jdkCurve = when (val crv = jwk.path("crv").asText()) {
                "P-256" -> "secp256r1"
                "P-384" -> "secp384r1"
                "P-521" -> "secp521r1"
                else -> error("unsupported crv $crv")
            }
            val params = AlgorithmParameters.getInstance("EC")
                .apply { init(ECGenParameterSpec(jdkCurve)) }
                .getParameterSpec(ECParameterSpec::class.java)
            KeyFactory.getInstance("EC").generatePublic(
                ECPublicKeySpec(ECPoint(int(jwk, "x"), int(jwk, "y")), params),
            )
        }

        "OKP" -> {
            val spki = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
            KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(spki + b64(jwk.path("x").asText())))
        }

        else -> error("unsupported kty $kty")
    }

    private fun int(jwk: JsonNode, field: String) = BigInteger(1, b64(jwk.path(field).asText()))

    private fun b64(value: String) = decoder.decode(value.padEnd((value.length + 3) / 4 * 4, '='))
}
