package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.support.Json
import com.nitrokey.nethsm.keycloak.support.Jws
import com.nitrokey.nethsm.keycloak.support.Keycloak
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.MethodOrderer
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestMethodOrder
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Rotating from one NetHSM key to the next without invalidating tokens already issued.
 *
 * The flow is one component per key generation: stand the new one up active at a higher
 * priority, then flip the old one passive so it keeps verifying until its tokens expire.
 * These tests pin the Keycloak behaviour that flow depends on, because none of it is
 * obvious from the configuration.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation::class)
class RotationIT {

    private val keycloak = Keycloak()
    private val realm = "it-rotation"
    private val old = "kc-rot-2026a"
    private val new = "kc-rot-2026b"

    @BeforeAll
    fun setUp() {
        keycloak.awaitReady()
        NetHsm.awaitOperational()
        keycloak.deleteRealm(realm)
        keycloak.createRealm(realm)
        keycloak.setDefaultSignatureAlgorithm(realm, "RS256")
    }

    @AfterAll
    fun tearDown() = keycloak.deleteRealm(realm)

    private fun signingKid(): String {
        val response = keycloak.serviceAccountToken(realm)
        assertEquals(200, response.statusCode(), "token request failed: ${response.body()}")
        val token = Json.read(response.body()).path("access_token").asText()
        return Jws.decodeHeader(token).path("kid").asText()
    }

    private fun publishedKids(): List<String> =
        keycloak.jwks(realm).path("keys").map { it.path("kid").asText() }.filter { it.startsWith("kc-rot") }

    @Test
    @Order(1)
    fun `the outgoing generation signs before rotation`() {
        keycloak.registerNetHsmProvider(realm, "nethsm-old", keyPrefix = old, algorithm = "RS256", priority = 200)
        assertEquals(old, signingKid())
    }

    /**
     * A component matching several keys is not a rotation mechanism: Keycloak takes the
     * first key the provider yields, which this extension orders by id. Adding a second
     * key under a shared prefix therefore does *not* hand over signing.
     */
    @Test
    @Order(2)
    fun `a broader prefix does not hand over signing, it just publishes both`() {
        keycloak.registerNetHsmProvider(realm, "nethsm-both", keyPrefix = "kc-rot", algorithm = "RS256", priority = 300)

        assertEquals(old, signingKid(), "the id-ordered first key keeps signing")
        assertTrue(publishedKids().containsAll(listOf(old, new)), "both are published: ${publishedKids()}")
    }

    @Test
    @Order(3)
    fun `a higher-priority component for the new key takes over signing`() {
        keycloak.registerNetHsmProvider(realm, "nethsm-new", keyPrefix = new, algorithm = "RS256", priority = 400)
        assertEquals(new, signingKid())
    }

    /**
     * The point of the whole exercise: tokens signed before the cutover must still
     * verify, so the outgoing key has to stay in the JWKS while it is passive.
     */
    @Test
    @Order(4)
    fun `the outgoing key stays published once passive, so old tokens still verify`() {
        keycloak.makePassive(realm, "nethsm-old", keyPrefix = old, algorithm = "RS256", priority = 200)
        keycloak.makePassive(realm, "nethsm-both", keyPrefix = "kc-rot", algorithm = "RS256", priority = 300)

        assertEquals(new, signingKid(), "signing must stay on the new key")
        assertTrue(old in publishedKids(), "outgoing key must remain verifiable: ${publishedKids()}")

        val statuses = Json.read(keycloak.realmKeys(realm).body()).path("keys")
            .filter { it.path("kid").asText() == old }
            .map { it.path("status").asText() }
        assertTrue(statuses.contains("PASSIVE"), "outgoing key should be PASSIVE, got $statuses")
    }
}
