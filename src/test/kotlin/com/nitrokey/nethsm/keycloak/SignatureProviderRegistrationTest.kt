package com.nitrokey.nethsm.keycloak

import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.SignatureProviderFactory
import java.util.ServiceLoader
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Guard rails. These catch the two ways this extension breaks silently:
 * a factory that is compiled but never registered, and an `order()` that no longer
 * beats Keycloak's built-in factory for the same id.
 */
class SignatureProviderRegistrationTest {

    private val ours = ServiceLoader.load(SignatureProviderFactory::class.java)
        .filter { it.javaClass.packageName.startsWith("com.nitrokey") }

    @Test
    fun `every registered factory reports the algorithm it is named after`() {
        assertTrue(ours.isNotEmpty(), "no factories found via ServiceLoader")
        ours.forEach { factory ->
            val expected = factory.javaClass.simpleName.removeSuffix("SignatureProviderFactory")
            assertEquals(expected, factory.id, "id must equal the algorithm to shadow the built-in")
        }
    }

    @Test
    fun `factories outrank the built-in factories they shadow`() {
        ours.forEach { factory ->
            assertTrue(factory.order() > 0, "${factory.id} must have order > 0 (built-ins use 0)")
        }
    }

    @Test
    fun `the algorithms Keycloak can sign with are all covered`() {
        val covered = ours.map { it.id }.toSet()
        val expected = setOf(
            Algorithm.RS256, Algorithm.RS384, Algorithm.RS512,
            Algorithm.PS256, Algorithm.PS384, Algorithm.PS512,
            Algorithm.ES256, Algorithm.ES384, Algorithm.ES512,
            Algorithm.EdDSA,
        )
        assertEquals(expected, covered)
    }

    @Test
    fun `each factory exposes a non-empty private JWK claim set`() {
        ours.forEach { factory ->
            assertTrue(
                factory.jwkPrivateKeyClaims.isNotEmpty(),
                "${factory.id} returned no jwkPrivateKeyClaims",
            )
        }
    }
}
