package com.nitrokey.nethsm.keycloak.jca

import com.nitrokey.nethsm.keycloak.NetHsmPrivateKeyHandle
import com.nitrokey.nethsm.keycloak.client.MessageSigner
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * What this provider sends to NetHSM, given a JCA signature request.
 *
 * The framing is the whole job here: `PKCS1` signs the submitted bytes verbatim, so an
 * EMSA-PKCS1-v1_5 signature only comes out if the DigestInfo header is prepended, while
 * `PSS_*` and `ECDSA` want the bare digest and Ed25519 the message itself. Getting that
 * wrong produces a signature that is well-formed and simply does not verify, which is
 * why these assert on the exact bytes rather than on a round trip.
 */
class NetHsmSignatureSpiTest {

    private class RecordingSigner : MessageSigner {
        var keyId: String? = null
        var mode: String? = null
        var message: ByteArray? = null

        override fun sign(keyId: String, mode: String, message: ByteArray): ByteArray {
            this.keyId = keyId
            this.mode = mode
            this.message = message
            return byteArrayOf(1, 2, 3)
        }
    }

    private val signer = RecordingSigner()
    private val data = "the quick brown fox".toByteArray()

    private fun handle(algorithm: String = "RSA") =
        NetHsmPrivateKeyHandle("kc-key", algorithm, signer = signer)

    @BeforeTest
    fun installProvider() {
        NetHsmSecurityProvider.install()
    }

    private fun signWith(algorithm: String): Signature =
        Signature.getInstance(algorithm).apply {
            initSign(handle())
            update(data)
            sign()
        }

    // --- what reaches NetHSM ---------------------------------------------------------

    @Test
    fun `PKCS1 gets the DigestInfo header, because NetHSM signs the bytes verbatim`() {
        signWith("SHA256withRSA")

        assertEquals("kc-key", signer.keyId)
        assertEquals("PKCS1", signer.mode)
        val expected = NetHsmSignatureSpiFixtures.digestInfo("SHA-256") +
            MessageDigest.getInstance("SHA-256").digest(data)
        assertContentEquals(expected, signer.message)
    }

    @Test
    fun `each RSA digest maps to its own header and the same PKCS1 mode`() {
        for ((algorithm, digest) in listOf(
            "SHA1withRSA" to "SHA-1",
            "SHA256withRSA" to "SHA-256",
            "SHA384withRSA" to "SHA-384",
            "SHA512withRSA" to "SHA-512",
        )) {
            signWith(algorithm)
            assertEquals("PKCS1", signer.mode, algorithm)
            val expected = NetHsmSignatureSpiFixtures.digestInfo(digest) +
                MessageDigest.getInstance(digest).digest(data)
            assertContentEquals(expected, signer.message, algorithm)
        }
    }

    @Test
    fun `PSS sends a bare digest under the matching NetHSM mode`() {
        for ((algorithm, digest, mode) in listOf(
            Triple("SHA256withRSAandMGF1", "SHA-256", "PSS_SHA256"),
            Triple("SHA384withRSAandMGF1", "SHA-384", "PSS_SHA384"),
            Triple("SHA512withRSAandMGF1", "SHA-512", "PSS_SHA512"),
        )) {
            signWith(algorithm)
            assertEquals(mode, signer.mode, algorithm)
            assertContentEquals(MessageDigest.getInstance(digest).digest(data), signer.message, algorithm)
        }
    }

    @Test
    fun `ECDSA sends a bare digest, since JOSE fixed-width conversion is not JCA's shape`() {
        signWith("SHA256withECDSA")
        assertEquals("ECDSA", signer.mode)
        assertContentEquals(MessageDigest.getInstance("SHA-256").digest(data), signer.message)
    }

    /** Ed25519 hashes internally and derives its nonce from that hash. */
    @Test
    fun `Ed25519 sends the message itself, not a digest`() {
        Signature.getInstance("Ed25519").apply {
            initSign(NetHsmPrivateKeyHandle("kc-ed", "Ed25519", signer = signer))
            update(data)
            sign()
        }
        assertEquals("EdDSA", signer.mode)
        assertContentEquals(data, signer.message)
    }

    @Test
    fun `the signature is returned exactly as NetHSM produced it`() {
        val produced = Signature.getInstance("SHA256withRSA").run {
            initSign(handle()); update(data); sign()
        }
        assertContentEquals(byteArrayOf(1, 2, 3), produced)
    }

    // --- what is refused --------------------------------------------------------------

    /** InvalidKeyException is how JCA is told to try the next provider. */
    @Test
    fun `an ordinary RSA key is refused so the platform provider handles it`() {
        val software = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertFailsWith<InvalidKeyException> {
            Signature.getInstance("SHA256withRSA", NetHsmSecurityProvider.NAME).initSign(software.private)
        }
    }

    @Test
    fun `a handle with no signer attached is refused`() {
        assertFailsWith<InvalidKeyException> {
            Signature.getInstance("SHA256withRSA", NetHsmSecurityProvider.NAME)
                .initSign(NetHsmPrivateKeyHandle("kc-key", "RSA"))
        }
    }

    @Test
    fun `verification is refused, so it stays local`() {
        val software = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertFailsWith<InvalidKeyException> {
            Signature.getInstance("SHA256withRSA", NetHsmSecurityProvider.NAME)
                .initVerify(software.public)
        }
    }

    @Test
    fun `PSS parameters that disagree with the mode are refused rather than ignored`() {
        val signature = Signature.getInstance("SHA256withRSAandMGF1", NetHsmSecurityProvider.NAME)
        signature.initSign(handle())

        // MGF1 on a different digest than the message digest: NetHSM cannot express it.
        assertFailsWith<InvalidAlgorithmParameterException> {
            signature.setParameter(
                PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, 32, 1),
            )
        }
        // A salt length NetHSM does not use.
        assertFailsWith<InvalidAlgorithmParameterException> {
            signature.setParameter(
                PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20, 1),
            )
        }
    }

    @Test
    fun `PSS parameters matching the mode are accepted`() {
        val signature = Signature.getInstance("SHA256withRSAandMGF1", NetHsmSecurityProvider.NAME)
        signature.initSign(handle())
        signature.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
        signature.update(data)
        assertTrue(signature.sign().isNotEmpty())
    }

    /** A rejected init must not leave the previous key usable. */
    @Test
    fun `a failed init clears the previous key`() {
        val signature = Signature.getInstance("SHA256withRSA", NetHsmSecurityProvider.NAME)
        signature.initSign(handle())

        assertFailsWith<InvalidKeyException> {
            signature.initSign(NetHsmPrivateKeyHandle("kc-other", "RSA"))
        }
        signature.update(data)
        assertFailsWith<java.security.SignatureException> { signature.sign() }
    }
}

/** RFC 8017 A.2.4 headers, spelled out here so the test does not read them from the code under test. */
internal object NetHsmSignatureSpiFixtures {
    private val HEADERS = mapOf(
        "SHA-1" to "3021300906052b0e03021a05000414",
        "SHA-256" to "3031300d060960864801650304020105000420",
        "SHA-384" to "3041300d060960864801650304020205000430",
        "SHA-512" to "3051300d060960864801650304020305000440",
    )

    fun digestInfo(digest: String): ByteArray =
        HEADERS.getValue(digest).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
