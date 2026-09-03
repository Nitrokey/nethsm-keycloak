package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.support.Json
import com.nitrokey.nethsm.keycloak.support.Keycloak
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A NetHSM key published for JWE key management rather than signing.
 *
 * Keycloak uses a realm ENC key in one direction only: decrypting inbound JWE, such as
 * an encrypted request object. Encrypting *to* a client uses that client's public key
 * and never involves the HSM, which is why there is no encryption case here.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EncryptionKeyIT {

    private val keycloak = Keycloak()
    private val realm = "it-encryption"

    @BeforeAll
    fun setUp() {
        keycloak.awaitReady()
        NetHsm.awaitOperational()
        keycloak.deleteRealm(realm)
        keycloak.createRealm(realm)
    }

    @AfterAll
    fun tearDown() = keycloak.deleteRealm(realm)

    @Test
    fun `an OAEP key is published for encryption use and appears in the JWKS`() {
        keycloak.registerNetHsmProvider(
            realm, "nethsm-enc", keyPrefix = "kc-rsa-oaep",
            algorithm = "RSA-OAEP-256", keyUse = "enc",
        )

        val keys = Json.read(keycloak.realmKeys(realm).body()).path("keys")
            .filter { it.path("algorithm").asText() == "RSA-OAEP-256" }
        assertEquals(listOf("kc-rsa-oaep"), keys.map { it.path("kid").asText() })

        val jwk = keycloak.jwk(realm, "kc-rsa-oaep")
        assertEquals("RSA", jwk.path("kty").asText())
        assertEquals("enc", jwk.path("use").asText(), "must be published for encryption use")
        assertTrue(jwk.path("n").isTextual, "public modulus must be published")
        listOf("d", "p", "q").forEach {
            assertTrue(jwk.path(it).isMissingNode, "JWKS leaked private field '$it'")
        }
    }

    @Test
    fun `a signing key is not published under an encryption algorithm`() {
        // kc-rsa-pkcs1 has only signature mechanisms, so an enc component over it yields nothing.
        keycloak.registerNetHsmProvider(
            realm, "nethsm-enc-wrong", keyPrefix = "kc-rsa-pkcs1",
            algorithm = "RSA-OAEP", keyUse = "enc", priority = 300,
        )

        val kids = Json.read(keycloak.realmKeys(realm).body()).path("keys")
            .filter { it.path("algorithm").asText() == "RSA-OAEP" }
            .map { it.path("kid").asText() }
        assertTrue(kids.none { it.startsWith("kc-") }, "signing key must not serve JWE: $kids")
    }

    @Test
    fun `an encryption algorithm is rejected for signing use`() {
        val response = keycloak.registerNetHsmProvider(
            realm, "nethsm-bad", keyPrefix = "kc-rsa-oaep",
            algorithm = "RSA-OAEP-256", keyUse = "sig",
        )
        assertTrue(
            response.statusCode() >= 400,
            "mismatched key use must be refused at validation, got ${response.statusCode()}",
        )
    }
}
