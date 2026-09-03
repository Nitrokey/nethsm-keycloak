package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.support.Jwe
import com.nitrokey.nethsm.keycloak.support.Keycloak
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The end-to-end exercise of JWE unwrapping: an encrypted request object posted to the
 * authorization endpoint, which Keycloak can only act on if it unwrapped the content
 * encryption key inside NetHSM.
 *
 * `prompt=none` makes the success signal machine-readable. With no session Keycloak
 * redirects to the client with `error=login_required`, which it can only reach after
 * parsing the decrypted request object. A failure to decrypt cannot produce that.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RequestObjectIT {

    private val keycloak = Keycloak()
    private val realm = "it-requestobject"
    private val clientId = "ro-client"
    private val redirectUri = "http://localhost:9999/callback"

    @BeforeAll
    fun setUp() {
        keycloak.awaitReady()
        NetHsm.awaitOperational()
        keycloak.deleteRealm(realm)
        keycloak.createRealm(realm)

        // signature.alg=none keeps the inner JWT unsigned, so this test is about
        // decryption alone and needs no client signing key.
        keycloak.createClient(
            realm,
            """{"clientId":"$clientId","enabled":true,"publicClient":true,
                "standardFlowEnabled":true,"redirectUris":["$redirectUri"],
                "attributes":{"request.object.signature.alg":"none",
                              "request.object.encryption.alg":"RSA-OAEP-256",
                              "request.object.encryption.enc":"A256GCM"}}""",
        )

        keycloak.registerNetHsmProvider(
            realm, "nethsm-enc", keyPrefix = "kc-rsa-oaep",
            algorithm = "RSA-OAEP-256", keyUse = "enc",
        )
    }

    @AfterAll
    fun tearDown() = keycloak.deleteRealm(realm)

    private fun encryptedRequestObject(): String {
        val claims = """{"client_id":"$clientId","response_type":"code",
                         "redirect_uri":"$redirectUri","scope":"openid","prompt":"none"}"""
        return Jwe.encrypt(Jwe.unsignedJwt(claims), keycloak.jwk(realm, "kc-rsa-oaep"))
    }

    private fun authorize(request: String) = keycloak.authorize(
        realm,
        mapOf(
            "client_id" to clientId,
            "response_type" to "code",
            "redirect_uri" to redirectUri,
            "scope" to "openid",
            "request" to request,
        ),
    )

    @Test
    fun `Keycloak acts on a request object whose CEK was unwrapped inside NetHSM`() {
        val response = authorize(encryptedRequestObject())
        val location = response.headers().firstValue("Location").orElse("")

        assertEquals(302, response.statusCode(), "expected a redirect, body was: ${response.body().take(300)}")
        assertTrue(
            location.startsWith(redirectUri),
            "must redirect to the client, so the object was parsed; got: $location",
        )
        assertTrue(
            "error=login_required" in location,
            "prompt=none inside the encrypted object must take effect; got: $location",
        )
    }

    /**
     * Asserts the status explicitly rather than merely "not login_required". The looser
     * form is satisfied by *any* failure, so it passed while the positive case was also
     * failing and proved nothing.
     */
    @Test
    fun `a request object whose CEK cannot be unwrapped is refused`() {
        val response = authorize(Jwe.withCorruptedCek(encryptedRequestObject()))
        val location = response.headers().firstValue("Location").orElse("")

        assertEquals(400, response.statusCode(), "an unusable CEK must be a bad request")
        assertTrue(
            "error=login_required" !in location,
            "must not be treated as a valid request; got: $location",
        )
    }
}
