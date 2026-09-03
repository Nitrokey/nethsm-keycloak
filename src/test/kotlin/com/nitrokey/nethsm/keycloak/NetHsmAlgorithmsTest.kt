package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmKey
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.ECDSAAlgorithm
import org.keycloak.jose.jwe.JWEConstants
import java.security.KeyPairGenerator
import java.security.PublicKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NetHsmAlgorithmsTest {

    private companion object {
        /**
         * `ECDSAAlgorithm`'s DER converters resolve a `CryptoProvider` through
         * `CryptoIntegration`, which a running Keycloak initialises during startup.
         * Without this, the conversion fails with "Illegal state. Please init first".
         */
        init {
            if (!CryptoIntegration.isInitialised()) {
                CryptoIntegration.init(NetHsmAlgorithmsTest::class.java.classLoader)
            }
        }
    }

    private val publicKey: PublicKey = KeyPairGenerator.getInstance("RSA")
        .apply { initialize(2048) }
        .generateKeyPair().public

    private fun key(type: String, vararg mechanisms: String) =
        NetHsmKey("k", type, mechanisms.toSet(), publicKey)

    @Test
    fun `a PKCS1 key serves every RS algorithm because the mechanism is hash-agnostic`() {
        assertEquals(
            setOf(Algorithm.RS256, Algorithm.RS384, Algorithm.RS512),
            NetHsmAlgorithms.supportedAlgorithms(key("RSA", "RSA_Signature_PKCS1")),
        )
    }

    @Test
    fun `a PSS key serves only the algorithm its mechanism names`() {
        assertEquals(
            setOf(Algorithm.PS256),
            NetHsmAlgorithms.supportedAlgorithms(key("RSA", "RSA_Signature_PSS_SHA256")),
        )
    }

    @Test
    fun `mechanisms combine`() {
        val supported = NetHsmAlgorithms.supportedAlgorithms(
            key("RSA", "RSA_Signature_PKCS1", "RSA_Signature_PSS_SHA384"),
        )
        assertTrue(Algorithm.RS512 in supported)
        assertTrue(Algorithm.PS384 in supported)
        assertTrue(Algorithm.PS256 !in supported)
    }

    @Test
    fun `a decrypt-only key is not usable for signing`() {
        assertTrue(NetHsmAlgorithms.supportedAlgorithms(key("RSA", "RSA_Decryption_PKCS1")).isEmpty())
    }

    @Test
    fun `each EC curve implies exactly one algorithm`() {
        assertEquals(setOf(Algorithm.ES256), NetHsmAlgorithms.supportedAlgorithms(key("EC_P256", "ECDSA_Signature")))
        assertEquals(setOf(Algorithm.ES384), NetHsmAlgorithms.supportedAlgorithms(key("EC_P384", "ECDSA_Signature")))
        assertEquals(setOf(Algorithm.ES512), NetHsmAlgorithms.supportedAlgorithms(key("EC_P521", "ECDSA_Signature")))
    }

    @Test
    fun `Curve25519 implies EdDSA`() {
        assertEquals(
            setOf(Algorithm.EdDSA),
            NetHsmAlgorithms.supportedAlgorithms(key("Curve25519", "EdDSA_Signature")),
        )
    }

    @Test
    fun `curves NetHSM offers but JOSE has no algorithm for are skipped`() {
        assertTrue(NetHsmAlgorithms.supportedAlgorithms(key("EC_P256K1", "ECDSA_Signature")).isEmpty())
        assertTrue(NetHsmAlgorithms.supportedAlgorithms(key("BrainpoolP256", "ECDSA_Signature")).isEmpty())
    }

    @Test
    fun `a key without the matching signature mechanism is skipped`() {
        assertTrue(NetHsmAlgorithms.supportedAlgorithms(key("EC_P256", "EdDSA_Signature")).isEmpty())
        assertTrue(NetHsmAlgorithms.supportedAlgorithms(key("Curve25519", "ECDSA_Signature")).isEmpty())
    }

    @Test
    fun `only Ed25519 gets the raw message`() {
        assertTrue(NetHsmAlgorithms.signsRawMessage(Algorithm.EdDSA))
        listOf(Algorithm.RS256, Algorithm.PS256, Algorithm.ES256).forEach {
            assertTrue(!NetHsmAlgorithms.signsRawMessage(it), "$it must be pre-hashed")
        }
    }

    @Test
    fun `curve is reported for EC and Curve25519 but not RSA`() {
        assertEquals("P-256", NetHsmAlgorithms.curveFor("EC_P256"))
        assertEquals("P-521", NetHsmAlgorithms.curveFor("EC_P521"))
        assertEquals("Ed25519", NetHsmAlgorithms.curveFor("Curve25519"))
        assertNull(NetHsmAlgorithms.curveFor("RSA"))
    }

    /**
     * NetHSM returns ECDSA as ASN.1 DER; JWS needs fixed-width r||s. Round-tripping
     * through Keycloak's own converters proves this extension and Keycloak's local EC
     * signer agree on the wire format.
     */
    @Test
    fun `ECDSA signatures are converted from DER to fixed-width r and s`() {
        listOf(Algorithm.ES256 to 64, Algorithm.ES384 to 96, Algorithm.ES512 to 132).forEach { (alg, len) ->
            val concatenated = ByteArray(len) { (it % 251 + 1).toByte() }
            val der = ECDSAAlgorithm.concatenatedRSToASN1DER(concatenated, len)
            assertContentEquals(concatenated, NetHsmAlgorithms.toJoseSignature(alg, der), alg)
        }
    }

    @Test
    fun `EdDSA and RSA signatures pass through untouched`() {
        val raw = ByteArray(64) { it.toByte() }
        assertContentEquals(raw, NetHsmAlgorithms.toJoseSignature(Algorithm.EdDSA, raw))
        assertContentEquals(raw, NetHsmAlgorithms.toJoseSignature(Algorithm.RS256, raw))
    }

    @Test
    fun `decrypt mechanisms decide which key-management algorithms a key serves`() {
        assertEquals(
            setOf(JWEConstants.RSA_OAEP_256),
            NetHsmAlgorithms.supportedEncryptionAlgorithms(key("RSA", "RSA_Decryption_OAEP_SHA256")),
        )
        assertEquals(
            setOf(JWEConstants.RSA_OAEP, JWEConstants.RSA_OAEP_256),
            NetHsmAlgorithms.supportedEncryptionAlgorithms(
                key("RSA", "RSA_Decryption_OAEP_SHA1", "RSA_Decryption_OAEP_SHA256"),
            ),
        )
    }

    @Test
    fun `signing and encryption use are not interchangeable`() {
        val signing = key("RSA", "RSA_Signature_PKCS1")
        val decrypting = key("RSA", "RSA_Decryption_OAEP_SHA256")

        assertTrue(NetHsmAlgorithms.supportedEncryptionAlgorithms(signing).isEmpty(), "a signing key is not a JWE key")
        assertTrue(NetHsmAlgorithms.supportedAlgorithms(decrypting).isEmpty(), "a decrypt key cannot sign")
    }

    @Test
    fun `a PKCS1 decrypt key is never offered, since RSA1_5 is excluded`() {
        assertTrue(NetHsmAlgorithms.supportedEncryptionAlgorithms(key("RSA", "RSA_Decryption_PKCS1")).isEmpty())
    }

    @Test
    fun `key-management algorithms map to NetHSM decrypt modes`() {
        assertEquals("OAEP_SHA1", NetHsmAlgorithms.decryptMode(JWEConstants.RSA_OAEP))
        assertEquals("OAEP_SHA256", NetHsmAlgorithms.decryptMode(JWEConstants.RSA_OAEP_256))
    }

    /**
     * Not an oversight in either case: RSA1_5 is a Bleichenbacher oracle on
     * attacker-supplied ciphertext, and ECDH-ES needs a key-agreement operation NetHSM
     * does not have.
     */
    @Test
    fun `RSA1_5 and ECDH-ES are refused rather than silently mapped`() {
        assertEquals(setOf(JWEConstants.RSA_OAEP, JWEConstants.RSA_OAEP_256), NetHsmAlgorithms.cekAlgorithms)
        listOf(JWEConstants.RSA1_5, JWEConstants.ECDH_ES, JWEConstants.ECDH_ES_A128KW).forEach {
            assertFailsWith<UnsupportedOperationException>("$it must not map") {
                NetHsmAlgorithms.decryptMode(it)
            }
        }
    }

    @Test
    fun `sign modes match the NetHSM API enum`() {
        assertEquals("PKCS1", NetHsmAlgorithms.signMode(Algorithm.RS256))
        assertEquals("PKCS1", NetHsmAlgorithms.signMode(Algorithm.RS512))
        assertEquals("PSS_SHA256", NetHsmAlgorithms.signMode(Algorithm.PS256))
        assertEquals("PSS_SHA512", NetHsmAlgorithms.signMode(Algorithm.PS512))
        assertEquals("ECDSA", NetHsmAlgorithms.signMode(Algorithm.ES256))
        assertEquals("ECDSA", NetHsmAlgorithms.signMode(Algorithm.ES512))
        assertEquals("EdDSA", NetHsmAlgorithms.signMode(Algorithm.EdDSA))
    }

    /**
     * The RS256 prefix is the one confirmed end to end against a real NetHSM: a digest
     * carrying it, signed in PKCS1 mode, verifies under `openssl dgst -sha256 -verify`.
     */
    @Test
    fun `RS algorithms carry the RFC 8017 DigestInfo header and PS algorithms do not`() {
        assertContentEquals(
            byteArrayOf(
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
            ),
            NetHsmAlgorithms.digestInfoPrefix(Algorithm.RS256),
        )
        assertEquals(19, NetHsmAlgorithms.digestInfoPrefix(Algorithm.RS384)?.size)
        assertEquals(19, NetHsmAlgorithms.digestInfoPrefix(Algorithm.RS512)?.size)
        assertNull(NetHsmAlgorithms.digestInfoPrefix(Algorithm.PS256))
    }

    /**
     * The header is a process-wide constant and a ByteArray is mutable, so the accessor
     * copies. Without this test the copy could be dropped as redundant, and the damage
     * would not show here: it would surface as signatures that stop verifying, in whatever
     * realm happened to sign after the corruption.
     */
    @Test
    fun `each caller gets its own copy of the DigestInfo header`() {
        val first = assertNotNull(NetHsmAlgorithms.digestInfoPrefix(Algorithm.RS256))
        first[0] = 0x00

        assertEquals(
            0x30.toByte(),
            assertNotNull(NetHsmAlgorithms.digestInfoPrefix(Algorithm.RS256))[0],
            "mutating a returned prefix corrupted the shared constant",
        )
    }
}
