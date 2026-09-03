package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.keycloak.crypto.Algorithm
import java.security.MessageDigest
import java.security.Signature
import kotlin.test.assertEquals
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
