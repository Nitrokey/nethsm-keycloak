package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.client.NetHsmUnavailableException
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.keycloak.crypto.Algorithm
import org.keycloak.jose.jwe.JWEConstants
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import java.security.MessageDigest
import java.security.Signature
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The one test where NetHSM, not Keycloak, is the subject.
 *
 * Every RSA algorithm rests on one NetHSM behaviour: `PKCS1` mode signs the submitted
 * bytes verbatim, so prefixing the digest with the RFC 8017 DigestInfo header yields an
 * EMSA-PKCS1-v1_5 signature. If a firmware change altered that, this fails with an
 * obvious cause instead of every RS* case failing for reasons that look like our bug.
 *
 * It deliberately uses the extension's own client and DigestInfo constants, so the thing
 * pinned is exactly the assumption the production path makes.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NetHsmContractIT {

    private lateinit var client: NetHsmClient

    private companion object {
        /**
         * Port 9 is discard: nothing listens on it in a test container, so the connection
         * is refused immediately rather than timing out.
         */
        const val DEAD_ENDPOINT = "https://127.0.0.1:9/api/v1"
    }

    @BeforeAll
    fun setUp() {
        NetHsm.awaitOperational()
        client = NetHsm.client()
    }

    @AfterAll
    fun tearDown() = client.close()

    @Test
    fun `NetHSM is provisioned and operational`() {
        assertTrue(client.ready(), "the testbed NetHSM should be Operational")
    }

    @Test
    fun `PKCS1 mode over a DigestInfo-prefixed digest produces an EMSA-PKCS1-v1_5 signature`() {
        val key = assertNotNull(client.key("kc-rsa-pkcs1"), "testbed key kc-rsa-pkcs1 is missing")
        assertEquals("RSA", key.type)

        val message = "the quick brown fox".toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(message)
        val prefix = assertNotNull(NetHsmAlgorithms.digestInfoPrefix(Algorithm.RS256))

        val signature = client.sign("kc-rsa-pkcs1", NetHsmAlgorithms.signMode(Algorithm.RS256), prefix + digest)

        val verifier = Signature.getInstance("SHA256withRSA").apply {
            initVerify(key.publicKey)
            update(message)
        }
        assertTrue(verifier.verify(signature), "NetHSM PKCS1 mode no longer produces RS256-compatible signatures")
    }

    /**
     * The JOSE side of the same problem. `RSA-OAEP-256` is RSAES-OAEP with SHA-256 *and*
     * MGF1-SHA256; NetHSM's API names only the digest and documents nothing about the
     * mask generation function, so this pins the observed behaviour in both directions.
     * If firmware ever moved to a fixed MGF1-SHA1, RSA-OAEP-256 would silently stop
     * interoperating and this test is what would say so.
     */
    @Test
    fun `OAEP decryption pairs MGF1 with the same digest, as JOSE requires`() {
        val key = assertNotNull(client.key("kc-rsa-oaep"), "testbed key kc-rsa-oaep is missing")
        val plaintext = "content-encryption-key".toByteArray()

        fun wrap(digest: String, mgf1: MGF1ParameterSpec): ByteArray =
            Cipher.getInstance("RSA/ECB/OAEPPadding").apply {
                init(
                    Cipher.ENCRYPT_MODE,
                    key.publicKey,
                    OAEPParameterSpec(digest, "MGF1", mgf1, PSource.PSpecified.DEFAULT),
                )
            }.doFinal(plaintext)

        listOf(
            Triple(JWEConstants.RSA_OAEP_256, "SHA-256", MGF1ParameterSpec.SHA256),
            Triple(JWEConstants.RSA_OAEP, "SHA-1", MGF1ParameterSpec.SHA1),
        ).forEach { (algorithm, digest, mgf1) ->
            val mode = NetHsmAlgorithms.decryptMode(algorithm)

            val unwrapped = client.decryptCek("kc-rsa-oaep", mode, wrap(digest, mgf1))
            assertContentEquals(plaintext, unwrapped, "$algorithm did not round-trip through $mode")

            // The negative direction is the one that proves MGF1 is not fixed.
            val mismatched = if (mgf1 == MGF1ParameterSpec.SHA256) MGF1ParameterSpec.SHA1 else MGF1ParameterSpec.SHA256
            assertFails("$mode accepted a mismatched MGF1, so MGF1 does not track the digest") {
                client.decryptCek("kc-rsa-oaep", mode, wrap(digest, mismatched))
            }
        }
    }

    /**
     * Round-robin failover, against real sockets.
     *
     * A deployment with one URL never exercises the rotation, so it could break without
     * any test noticing -- and it would then break at the moment it is most needed, when
     * an operator has added a second NetHSM expecting exactly this.
     */
    @Test
    fun `a dead endpoint is skipped for a live one`() {
        NetHsm.clientFor(listOf(DEAD_ENDPOINT, NetHsm.URL)).use {
            assertTrue(it.ready(), "should have failed over past the dead endpoint")
            assertNotNull(it.key("kc-rsa-pkcs1"), "and be usable, not merely reachable")
        }
        // Order must not matter: starting on the live endpoint works too.
        NetHsm.clientFor(listOf(NetHsm.URL, DEAD_ENDPOINT)).use {
            assertTrue(it.ready())
            assertNotNull(it.key("kc-rsa-pkcs1"))
        }
    }

    /** Fail closed: no endpoint left must raise, never quietly report success. */
    @Test
    fun `every endpoint being dead fails rather than succeeding`() {
        NetHsm.clientFor(listOf(DEAD_ENDPOINT, DEAD_ENDPOINT)).use {
            assertFalse(it.ready())
            assertFailsWith<NetHsmUnavailableException> { it.keyIds("kc-") }
        }
    }

    @Test
    fun `key metadata carries everything needed to build a JWK, so nothing has to be configured`() {
        listOf(
            "kc-rsa-pkcs1" to "RSA",
            "kc-ec-p256" to "EC_P256",
            "kc-ec-p384" to "EC_P384",
            "kc-ec-p521" to "EC_P521",
            "kc-ed25519" to "Curve25519",
        ).forEach { (id, expectedType) ->
            val key = assertNotNull(client.key(id), "testbed key $id is missing")
            assertEquals(expectedType, key.type, id)
            assertTrue(key.mechanisms.isNotEmpty(), "$id reported no mechanisms")
            assertTrue(
                NetHsmAlgorithms.supportedAlgorithms(key).isNotEmpty(),
                "$id (${key.type}, ${key.mechanisms}) maps to no JOSE algorithm",
            )
        }
    }
}
