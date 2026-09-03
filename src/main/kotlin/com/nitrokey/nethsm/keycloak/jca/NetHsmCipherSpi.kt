package com.nitrokey.nethsm.keycloak.jca

import com.nitrokey.nethsm.keycloak.NetHsmPrivateKeyHandle
import com.nitrokey.nethsm.keycloak.client.CekDecryptor
import com.nitrokey.nethsm.keycloak.client.NetHsmUnavailableException
import org.jboss.logging.Logger
import java.io.ByteArrayOutputStream
import java.security.AlgorithmParameters
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Key
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherSpi
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.OAEPParameterSpec

/**
 * RSA-OAEP decryption performed inside NetHSM, exposed as a JCA [CipherSpi].
 *
 * This is the hook, rather than a Keycloak SPI, because Keycloak only consults its
 * `CekManagementProvider` when *encrypting*. Inbound JWE is decrypted by
 * `DefaultRsaKeyEncryptionJWEAlgorithmProvider`, which does a plain
 * `Cipher.getInstance(transformation).init(DECRYPT_MODE, key)`. JCA defers provider
 * selection until that `init`, trying each candidate until one accepts the key -- so a
 * provider that accepts [NetHsmPrivateKeyHandle] gets selected with no change to
 * Keycloak. The same key then works in any other JCA path too.
 *
 * Every key that is not a NetHSM handle is rejected with [InvalidKeyException], which is
 * how JCA is told to move on. Combined with registering the provider last, ordinary RSA
 * keys keep using the platform implementation.
 */
class NetHsmCipherSpi : CipherSpi() {

    private var decryptMode: String? = null
    private var handle: NetHsmPrivateKeyHandle? = null
    private var decryptor: CekDecryptor? = null
    private val buffer = ByteArrayOutputStream()

    override fun engineSetMode(mode: String) {
        // RSA "ECB" is JCA's historical spelling for single-block RSA.
        if (!mode.equals("ECB", ignoreCase = true) && mode.isNotEmpty()) {
            throw NoSuchAlgorithmException("unsupported mode: $mode")
        }
    }

    /**
     * PKCS#1 v1.5 is deliberately absent. NetHSM can do it, but decrypting
     * attacker-chosen ciphertext with it is the classic Bleichenbacher oracle, so this
     * provider refuses and lets the platform handle any key that wants it.
     */
    override fun engineSetPadding(padding: String) {
        decryptMode = when (padding.uppercase()) {
            "OAEPWITHSHA-1ANDMGF1PADDING", "OAEPWITHSHA1ANDMGF1PADDING" -> "OAEP_SHA1"
            "OAEPWITHSHA-256ANDMGF1PADDING", "OAEPWITHSHA256ANDMGF1PADDING" -> "OAEP_SHA256"
            "OAEPWITHSHA-384ANDMGF1PADDING", "OAEPWITHSHA384ANDMGF1PADDING" -> "OAEP_SHA384"
            "OAEPWITHSHA-512ANDMGF1PADDING", "OAEPWITHSHA512ANDMGF1PADDING" -> "OAEP_SHA512"
            else -> throw NoSuchPaddingException("unsupported padding: $padding")
        }
    }

    override fun engineInit(opmode: Int, key: Key, random: SecureRandom?) {
        if (opmode != Cipher.DECRYPT_MODE && opmode != Cipher.UNWRAP_MODE) {
            // Encryption uses a public key and has no business reaching the HSM.
            throw InvalidKeyException("NetHSM keys can only decrypt or unwrap")
        }
        val netHsmKey = key as? NetHsmPrivateKeyHandle
            // Not an error: this is how JCA is told to try the next provider.
            ?: throw InvalidKeyException("not a NetHSM key")

        decryptor = netHsmKey.decryptor
            ?: throw InvalidKeyException("NetHSM key '${netHsmKey.keyId}' has no decryptor attached")
        handle = netHsmKey
    }

    override fun engineInit(opmode: Int, key: Key, params: AlgorithmParameterSpec?, random: SecureRandom?) {
        if (params is OAEPParameterSpec) {
            verifyOaepParameters(params)
        } else if (params != null) {
            throw InvalidAlgorithmParameterException("unsupported parameters: ${params.javaClass.name}")
        }
        engineInit(opmode, key, random)
    }

    override fun engineInit(opmode: Int, key: Key, params: AlgorithmParameters?, random: SecureRandom?) {
        engineInit(opmode, key, params?.getParameterSpec(OAEPParameterSpec::class.java), random)
    }

    /**
     * NetHSM's OAEP pairs MGF1 with the same digest as the message digest, so anything
     * else must be refused rather than silently decrypted under the wrong parameters.
     */
    private fun verifyOaepParameters(params: OAEPParameterSpec) {
        val digest = params.digestAlgorithm.uppercase().replace("-", "")
        val mgf1 = (params.mgfParameters as? MGF1ParameterSpec)
            ?.digestAlgorithm?.uppercase()?.replace("-", "")
            ?: throw InvalidAlgorithmParameterException("only MGF1 is supported")

        if (digest != mgf1) {
            throw InvalidAlgorithmParameterException(
                "NetHSM pairs MGF1 with the message digest; got digest=$digest mgf1=$mgf1",
            )
        }
        decryptMode = when (digest) {
            "SHA1" -> "OAEP_SHA1"
            "SHA256" -> "OAEP_SHA256"
            "SHA384" -> "OAEP_SHA384"
            "SHA512" -> "OAEP_SHA512"
            else -> throw InvalidAlgorithmParameterException("unsupported digest: $digest")
        }
    }

    override fun engineUpdate(input: ByteArray, offset: Int, len: Int): ByteArray? {
        buffer.write(input, offset, len)
        return null
    }

    override fun engineUpdate(input: ByteArray, offset: Int, len: Int, output: ByteArray, outputOffset: Int): Int {
        buffer.write(input, offset, len)
        return 0
    }

    override fun engineDoFinal(input: ByteArray?, offset: Int, len: Int): ByteArray {
        if (input != null && len > 0) buffer.write(input, offset, len)

        val key = handle ?: throw IllegalStateException("cipher not initialised")
        val mode = decryptMode ?: throw IllegalStateException("padding not set")
        val ciphertext = buffer.toByteArray()
        buffer.reset()

        return try {
            decryptor!!.decryptCek(key.keyId, mode, ciphertext)
        } catch (e: Exception) {
            // The uniformity is owed to the caller, not to the log: without a record
            // here, an unreachable NetHSM is indistinguishable from a malformed JWE in
            // the only place an operator can debug from.
            //
            // Split by level rather than logged at one, because the two cases differ in
            // who causes them. An outage is the server's problem and has to be visible;
            // a rejected ciphertext is routine and attacker-triggerable, so logging it
            // loudly would hand anyone a way to flood the log. Neither changes what the
            // caller is told.
            if (e is NetHsmUnavailableException) {
                log.errorf(e, "NetHSM is unreachable, so JWE sent to key '%s' cannot be decrypted", key.keyId)
            } else {
                log.debugf(e, "NetHSM did not unwrap a CEK with key '%s' (%s)", key.keyId, mode)
            }

            // Uniform on purpose: the ciphertext is attacker-supplied, and NetHSM
            // distinguishes a padding failure. BadPaddingException is what JCA callers
            // expect, and it carries no detail about which failure occurred.
            throw BadPaddingException("decryption failed")
        }
    }

    override fun engineDoFinal(
        input: ByteArray?,
        offset: Int,
        len: Int,
        output: ByteArray,
        outputOffset: Int,
    ): Int {
        val plaintext = engineDoFinal(input, offset, len)
        plaintext.copyInto(output, outputOffset)
        return plaintext.size
    }

    override fun engineGetBlockSize(): Int = 0

    override fun engineGetOutputSize(inputLen: Int): Int = inputLen

    override fun engineGetIV(): ByteArray? = null

    override fun engineGetParameters(): AlgorithmParameters? = null

    private class NoSuchAlgorithmException(message: String) : java.security.NoSuchAlgorithmException(message)

    private companion object {
        private val log = Logger.getLogger(NetHsmCipherSpi::class.java)
    }
}
