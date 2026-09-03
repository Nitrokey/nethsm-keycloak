package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.support.Json
import com.nitrokey.nethsm.keycloak.support.Jws
import com.nitrokey.nethsm.keycloak.support.Keycloak
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * What a realm ends up publishing, given a key prefix. Asserted through Keycloak's realm
 * keys and JWKS endpoints rather than by inspecting the extension.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DiscoveryIT {

    private val keycloak = Keycloak()
    private val realm = "it-discovery"

    @BeforeAll
    fun setUp() {
        keycloak.awaitReady()
        NetHsm.awaitOperational()
        keycloak.deleteRealm(realm)
        keycloak.createRealm(realm)
    }

    @AfterAll
    fun tearDown() = keycloak.deleteRealm(realm)

    private fun kidsFor(algorithm: String): List<String> =
        Json.read(keycloak.realmKeys(realm).body()).path("keys")
            .filter { it.path("algorithm").asText() == algorithm }
            .map { it.path("kid").asText() }

    @Test
    fun `a prefix matching several keys publishes only those that can serve the algorithm`() {
        // 'kc-rsa' matches both kc-rsa-pkcs1 and kc-rsa-pss, but only the PKCS1 key's
        // mechanisms can serve RS256.
        keycloak.registerNetHsmProvider(realm, "nethsm-rs256", keyPrefix = "kc-rsa", algorithm = "RS256")

        val kids = kidsFor("RS256")
        assertTrue("kc-rsa-pkcs1" in kids, "expected the PKCS1 key, got $kids")
        assertTrue("kc-rsa-pss" !in kids, "PSS key must not be published under RS256, got $kids")
    }

    @Test
    fun `the same prefix under a PSS algorithm publishes the PSS key instead`() {
        keycloak.registerNetHsmProvider(realm, "nethsm-ps384", keyPrefix = "kc-rsa", algorithm = "PS384")

        val kids = kidsFor("PS384")
        assertEquals(listOf("kc-rsa-pss"), kids)
    }

    @Test
    fun `a prefix matching nothing publishes nothing under that algorithm`() {
        keycloak.registerNetHsmProvider(realm, "nethsm-none", keyPrefix = "no-such-key", algorithm = "ES512")

        assertTrue(
            kidsFor("ES512").none { it.startsWith("kc-") },
            "no NetHSM key should be published for an unmatched prefix",
        )
    }

    /**
     * A misconfigured prefix is not an error anywhere: discovery succeeds and simply
     * matches nothing, so Keycloak falls back to the generated key every realm has by
     * default and keeps issuing tokens signed outside the HSM.
     *
     * Unlike an unreachable NetHSM, `on-unavailable=fail` does not cover this, because
     * nothing failed. Realms that must be HSM-only have to remove the generated
     * providers; see the README.
     */
    @Test
    fun `a prefix that matches nothing silently leaves signing to the generated key`() {
        keycloak.registerNetHsmProvider(
            realm, "nethsm-typo", keyPrefix = "kc-rsa-pkcs1-typo", algorithm = "RS256", priority = 400,
        )
        keycloak.setDefaultSignatureAlgorithm(realm, "RS256")

        val response = keycloak.serviceAccountToken(realm)
        assertEquals(200, response.statusCode(), "a typo must not break token issuance either")

        val token = Json.read(response.body()).path("access_token").asText()
        val kid = Jws.decodeHeader(token).path("kid").asText()
        assertTrue(
            !kid.startsWith("kc-"),
            "expected Keycloak's generated key, so the hazard is real; got $kid",
        )
    }

    @Test
    fun `kid is the NetHSM key id, so it is stable rather than generated`() {
        keycloak.registerNetHsmProvider(realm, "nethsm-eddsa", keyPrefix = "kc-ed25519", algorithm = "EdDSA")

        assertEquals(listOf("kc-ed25519"), kidsFor("EdDSA"))
        val jwk = keycloak.jwk(realm, "kc-ed25519")
        assertEquals("OKP", jwk.path("kty").asText())
        assertEquals("Ed25519", jwk.path("crv").asText())
    }
}
