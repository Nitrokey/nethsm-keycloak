package com.nitrokey.nethsm.keycloak.support

import com.fasterxml.jackson.databind.JsonNode
import java.math.BigInteger
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * Builds a compact JWE the way a relying party would, so the extension is exercised
 * through Keycloak's real parsing path rather than a test-only shortcut.
 *
 * Only `RSA-OAEP-256` + `A256GCM` is implemented -- that is what the request-object test
 * needs, and adding modes nobody exercises would just be untested code.
 */
object Jwe {

    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder: Base64.Decoder = Base64.getUrlDecoder()
    private val random = SecureRandom()

    /** Encrypts [plaintext] to the public key in [jwk], returning compact serialisation. */
    fun encrypt(plaintext: String, jwk: JsonNode): String {
        val header = encoder.encodeToString(
            """{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"${jwk.path("kid").asText()}"}""".toByteArray(),
        )

        val cek = ByteArray(32).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)

        val wrappedCek = Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
            init(
                Cipher.ENCRYPT_MODE,
                rsaPublicKey(jwk),
                // Explicit MGF1-SHA256: the JCA default for this transformation is
                // MGF1-SHA1, which would silently produce a JWE Keycloak cannot read.
                OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT),
            )
        }.doFinal(cek)

        // A256GCM: the protected header is the additional authenticated data, per RFC 7516.
        val sealed = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, iv))
            updateAAD(header.toByteArray())
        }.doFinal(plaintext.toByteArray())

        val ciphertext = sealed.copyOfRange(0, sealed.size - 16)
        val tag = sealed.copyOfRange(sealed.size - 16, sealed.size)

        return listOf(header, encoder.encodeToString(wrappedCek), encoder.encodeToString(iv),
            encoder.encodeToString(ciphertext), encoder.encodeToString(tag)).joinToString(".")
    }

    /** An unsigned JWT, for a client configured with `request.object.signature.alg=none`. */
    fun unsignedJwt(claims: String): String =
        encoder.encodeToString("""{"alg":"none"}""".toByteArray()) + "." +
            encoder.encodeToString(claims.toByteArray()) + "."

    /** Corrupts the wrapped CEK, leaving a structurally valid JWE that cannot be unwrapped. */
    fun withCorruptedCek(jwe: String): String {
        val parts = jwe.split(".")
        val wrapped = decoder.decode(parts[1])
        wrapped[0] = (wrapped[0].toInt() xor 0xff).toByte()
        return listOf(parts[0], encoder.encodeToString(wrapped), parts[2], parts[3], parts[4]).joinToString(".")
    }

    private fun rsaPublicKey(jwk: JsonNode) = KeyFactory.getInstance("RSA").generatePublic(
        RSAPublicKeySpec(
            BigInteger(1, decoder.decode(jwk.path("n").asText())),
            BigInteger(1, decoder.decode(jwk.path("e").asText())),
        ),
    )
}
