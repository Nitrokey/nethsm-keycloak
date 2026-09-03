package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.support.Json
import com.nitrokey.nethsm.keycloak.support.Jws
import com.nitrokey.nethsm.keycloak.support.Keycloak
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import kotlin.test.assertEquals

/**
 * The core end-to-end assertion, one case per algorithm: ask Keycloak for a token, and
 * check that it was signed by the NetHSM key and that the signature verifies against
 * what Keycloak publishes in its JWKS.
 *
 * Everything driven here is a Keycloak endpoint. NetHSM only appears as the source of
 * the keys `provision.sh` created.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SigningIT {

    private val keycloak = Keycloak()
    private val realm = "it-signing"

    @BeforeAll
    fun setUp() {
        keycloak.awaitReady()
        NetHsm.awaitOperational()
        keycloak.deleteRealm(realm)
        keycloak.createRealm(realm)
    }

    @AfterAll
    fun tearDown() = keycloak.deleteRealm(realm)

    @ParameterizedTest(name = "{0} signed by NetHSM key {1}")
    @CsvSource(
        "RS256, kc-rsa-pkcs1",
        "RS384, kc-rsa-pkcs1",
        "RS512, kc-rsa-pkcs1",
        "PS256, kc-rsa-pss",
        "PS384, kc-rsa-pss",
        "PS512, kc-rsa-pss",
        "ES256, kc-ec-p256",
        "ES384, kc-ec-p384",
        "ES512, kc-ec-p521",
        "EdDSA, kc-ed25519",
    )
    fun `token is signed inside the HSM and verifies against the realm JWKS`(
        algorithm: String,
        expectedKid: String,
    ) {
        // A component per algorithm; distinct names so they coexist in one realm.
        keycloak.registerNetHsmProvider(
            realm = realm,
            name = "nethsm-${algorithm.lowercase()}",
            keyPrefix = expectedKid,
            algorithm = algorithm,
        )
        keycloak.setDefaultSignatureAlgorithm(realm, algorithm)

        val response = keycloak.serviceAccountToken(realm)
        assertEquals(200, response.statusCode(), "token request failed: ${response.body()}")

        val token = Json.read(response.body()).path("access_token").asText()
        val header = Jws.decodeHeader(token)

        assertEquals(algorithm, header.path("alg").asText())
        assertEquals(expectedKid, header.path("kid").asText(), "token was not signed by the NetHSM key")

        // Independent verification: reconstruct the key from Keycloak's JWKS and check
        // the signature with the JDK, which is what a relying party would do.
        Jws.verify(token, keycloak.jwk(realm, expectedKid))
    }
}
