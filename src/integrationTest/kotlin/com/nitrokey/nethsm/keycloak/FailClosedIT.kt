package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.support.Compose
import com.nitrokey.nethsm.keycloak.support.Json
import com.nitrokey.nethsm.keycloak.support.Keycloak
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestMethodOrder
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The security property: an unreachable NetHSM must never turn into a silently generated
 * software key.
 *
 * `DefaultKeyManager` answers a realm with no active key by asking the generated key
 * provider factories for a fallback, so "the provider returned nothing" is not a neutral
 * outcome. These tests assert on what Keycloak publishes and issues, with NetHSM stopped.
 *
 * Admin authentication stays on `master`, which uses Keycloak's own keys -- otherwise
 * stopping NetHSM would also block the admin API these assertions need.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(org.junit.jupiter.api.MethodOrderer.OrderAnnotation::class)
class FailClosedIT {

    private val keycloak = Keycloak()
    private val realm = "it-failclosed"

    @BeforeAll
    fun setUp() {
        keycloak.awaitReady()
        NetHsm.awaitOperational()
        keycloak.deleteRealm(realm)
        keycloak.createRealm(realm)
    }

    @AfterAll
    fun tearDown() {
        // Always hand the stack back intact, whatever happened.
        runCatching { NetHsm.restart() }
        keycloak.deleteRealm(realm)
    }

    @Test
    @Order(1)
    fun `with NetHSM up the realm signs with the HSM key`() {
        keycloak.registerNetHsmProvider(realm, "nethsm-rs256", keyPrefix = "kc-rsa-pkcs1", algorithm = "RS256")
        keycloak.setDefaultSignatureAlgorithm(realm, "RS256")

        val response = keycloak.serviceAccountToken(realm)
        assertEquals(200, response.statusCode())
        val token = Json.read(response.body()).path("access_token").asText()
        assertEquals("kc-rsa-pkcs1", com.nitrokey.nethsm.keycloak.support.Jws.decodeHeader(token).path("kid").asText())
    }

    @Test
    @Order(2)
    fun `a cold cache with NetHSM down fails closed and generates no software key`() {
        Compose.stop("nethsm")
        try {
            // A prefix this Keycloak has never discovered, so nothing is cached for it.
            keycloak.registerNetHsmProvider(realm, "nethsm-es384", keyPrefix = "kc-ec-p384", algorithm = "ES384")

            val keys = keycloak.realmKeys(realm)
            assertNotEquals(200, keys.statusCode(), "discovery must not silently succeed with NetHSM down")

            // The decisive check: Keycloak must not have invented an ES384 key. Read it
            // back once NetHSM is up again, so the endpoint can answer.
            NetHsm.restart()
            val afterRecovery = Json.read(keycloak.realmKeys(realm).body()).path("keys")
            val es384 = afterRecovery.filter { it.path("algorithm").asText() == "ES384" }
            assertTrue(
                es384.all { it.path("kid").asText() == "kc-ec-p384" },
                "a software ES384 key was generated: ${es384.map { it.path("kid").asText() }}",
            )
        } finally {
            NetHsm.restart()
        }
    }

    @Test
    @Order(3)
    fun `a warm cache with NetHSM down still publishes the key and fails at signing`() {
        // RS256 was discovered in the first test, so its metadata is cached.
        Compose.stop("nethsm")
        try {
            val response = keycloak.serviceAccountToken(realm)
            assertNotEquals(200, response.statusCode(), "signing must fail rather than fall back")
            assertTrue(
                Json.read(response.body()).path("access_token").isMissingNode,
                "no token should be issued while the HSM is unreachable",
            )
        } finally {
            NetHsm.restart()
        }
    }
}
