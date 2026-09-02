package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmKey
import org.keycloak.crypto.Algorithm
import java.security.KeyPairGenerator
import java.security.PublicKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NetHsmAlgorithmsTest {

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
    fun `EC and Curve25519 are not claimed yet`() {
        assertTrue(NetHsmAlgorithms.supportedAlgorithms(key("EC_P256", "ECDSA_Signature")).isEmpty())
        assertTrue(NetHsmAlgorithms.supportedAlgorithms(key("Curve25519", "EdDSA_Signature")).isEmpty())
    }

    @Test
    fun `sign modes match the NetHSM API enum`() {
        assertEquals("PKCS1", NetHsmAlgorithms.signMode(Algorithm.RS256))
        assertEquals("PKCS1", NetHsmAlgorithms.signMode(Algorithm.RS512))
        assertEquals("PSS_SHA256", NetHsmAlgorithms.signMode(Algorithm.PS256))
        assertEquals("PSS_SHA512", NetHsmAlgorithms.signMode(Algorithm.PS512))
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
