package com.nitrokey.nethsm.keycloak.jca

import com.nitrokey.nethsm.keycloak.NetHsmPrivateKeyHandle
import com.nitrokey.nethsm.keycloak.client.CekDecryptor
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.spec.MGF1ParameterSpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.ShortBufferException
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The JCA provider is the whole mechanism by which an HSM-held key reaches Keycloak's
 * decryption path, and it installs global crypto surface, so both halves matter: that it
 * accepts NetHSM keys, and that it stays out of the way of everything else.
 */
class NetHsmCipherSpiTest {

    private val plaintext = "content-encryption-key".toByteArray()
    private val recording = mutableListOf<Triple<String, String, ByteArray>>()

    private val decryptor = CekDecryptor { id, mode, ciphertext ->
        recording += Triple(id, mode, ciphertext)
        plaintext
    }

    private fun handle(with: CekDecryptor? = decryptor) = NetHsmPrivateKeyHandle("kc-enc", "RSA", with)


    // --- the property that makes JCA provider selection work -------------------------

    @Test
    fun `an ordinary RSA key is rejected, which is how JCA is told to try the next provider`() {
        val softwareKey = KeyPairGenerator.getInstance("RSA")
            .apply { initialize(2048) }.generateKeyPair().private

        val failure = assertFailsWith<InvalidKeyException> {
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", NetHsmSecurityProvider())
                .init(Cipher.DECRYPT_MODE, softwareKey)
        }
        assertTrue("not a NetHSM key" in failure.message.orEmpty())
    }

    /**
     * The end-to-end mechanism: Keycloak calls `Cipher.getInstance(...).init(key)` with no
     * provider named, and JCA has to land on this provider because the platform rejects
     * the opaque key. If this breaks, JWE decryption silently stops using the HSM.
     */
    @Test
    fun `JCA selects this provider for a NetHSM key with no provider named`() {
        NetHsmSecurityProvider.install()

        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, handle())
        val out = cipher.doFinal("wrapped".toByteArray())

        assertEquals(NetHsmSecurityProvider.NAME, cipher.provider.name)
        assertContentEquals(plaintext, out)
        assertEquals("OAEP_SHA256", recording.single().second)
    }

    @Test
    fun `installing the provider leaves ordinary RSA working on the platform implementation`() {
        NetHsmSecurityProvider.install()

        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val transformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

        val sealed = Cipher.getInstance(transformation)
            .apply { init(Cipher.ENCRYPT_MODE, pair.public) }.doFinal(plaintext)
        val opened = Cipher.getInstance(transformation)
            .apply { init(Cipher.DECRYPT_MODE, pair.private) }

        assertTrue(opened.provider.name != NetHsmSecurityProvider.NAME, "must not hijack ordinary keys")
        assertContentEquals(plaintext, opened.doFinal(sealed))
    }

    @Test
    fun `install is idempotent, so provider ordering cannot drift`() {
        NetHsmSecurityProvider.install()
        val before = java.security.Security.getProviders().size
        NetHsmSecurityProvider.install()
        assertEquals(before, java.security.Security.getProviders().size)
    }

    // --- refusals ---------------------------------------------------------------------

    @Test
    fun `encryption is refused, because it would use a public key and never needs the HSM`() {
        assertFailsWith<InvalidKeyException> {
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", NetHsmSecurityProvider())
                .init(Cipher.ENCRYPT_MODE, handle())
        }
    }

    @Test
    fun `PKCS1 v1_5 padding is refused, so RSA1_5 can never be served from the HSM`() {
        assertFailsWith<NoSuchPaddingException> {
            Cipher.getInstance("RSA/ECB/PKCS1Padding", NetHsmSecurityProvider())
        }
    }

    @Test
    fun `each OAEP padding maps to the matching NetHSM decrypt mode`() {
        listOf("OAEPWithSHA-1AndMGF1Padding" to "OAEP_SHA1", "OAEPWithSHA-256AndMGF1Padding" to "OAEP_SHA256")
            .forEach { (padding, mode) ->
                recording.clear()
                Cipher.getInstance("RSA/ECB/$padding", NetHsmSecurityProvider()).apply {
                    init(Cipher.DECRYPT_MODE, handle())
                    doFinal("x".toByteArray())
                }
                assertEquals(mode, recording.single().second, padding)
            }
    }

    /** NetHSM pairs MGF1 with the message digest; anything else must fail, not be guessed at. */
    @Test
    fun `explicit parameters with a mismatched MGF1 digest are refused`() {
        assertFailsWith<InvalidAlgorithmParameterException> {
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", NetHsmSecurityProvider())
                .init(
                    Cipher.DECRYPT_MODE,
                    handle(),
                    OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT),
                )
        }
    }

    @Test
    fun `a key with no decryptor is refused rather than failing later`() {
        assertFailsWith<InvalidKeyException> {
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", NetHsmSecurityProvider())
                .init(Cipher.DECRYPT_MODE, handle(with = null))
        }
    }

    // --- failure handling --------------------------------------------------------------

    /**
     * The ciphertext is attacker-supplied and NetHSM answers a padding failure
     * distinguishably, so every failure has to look identical from outside. This replaces
     * coverage that was lost when the CEK-picker approach was removed.
     */
    @Test
    fun `every decrypt failure looks the same, whatever the cause`() {
        fun failWith(cause: Exception): String {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", NetHsmSecurityProvider())
            cipher.init(Cipher.DECRYPT_MODE, NetHsmPrivateKeyHandle("kc-enc", "RSA", { _, _, _ -> throw cause }))
            return assertFailsWith<BadPaddingException> { cipher.doFinal("x".toByteArray()) }.message.orEmpty()
        }

        val padding = failWith(IllegalStateException("HTTP 400: Decryption failure"))
        val outage = failWith(IllegalStateException("NetHSM unreachable after 3 attempts"))

        assertEquals(padding, outage, "a padding failure must be indistinguishable from an outage")
        listOf("Decryption failure", "400", "unreachable", "NetHSM").forEach {
            assertTrue(it !in padding, "leaked '$it': $padding")
        }
    }

    @Test
    fun `a too-small output buffer reports ShortBufferException, per the JCA contract`() {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", NetHsmSecurityProvider())
        cipher.init(Cipher.DECRYPT_MODE, handle())

        assertFailsWith<ShortBufferException> {
            cipher.doFinal("x".toByteArray(), 0, 1, ByteArray(1), 0)
        }
    }
}
