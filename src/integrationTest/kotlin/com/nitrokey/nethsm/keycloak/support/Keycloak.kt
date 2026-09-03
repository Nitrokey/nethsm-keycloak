package com.nitrokey.nethsm.keycloak.support

import com.fasterxml.jackson.databind.JsonNode
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * The Keycloak side of the testbed: everything the end-to-end tests drive.
 *
 * Each test class provisions its own realm. That isolates components and the realm's
 * default signature algorithm, and -- importantly -- keeps admin authentication on
 * `master`, which uses Keycloak's own generated keys. Otherwise a test that stops NetHSM
 * would also lock the tests out of the admin API they need to assert with.
 */
class Keycloak(private val baseUrl: String = BASE_URL) {

    private val http: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build()

    /** Blocks until Keycloak answers, then returns. */
    fun awaitReady(timeout: Duration = Duration.ofMinutes(3)) {
        val deadline = System.nanoTime() + timeout.toNanos()
        var last: Exception? = null
        while (System.nanoTime() < deadline) {
            try {
                if (get("/realms/master").statusCode() == 200) return
            } catch (e: Exception) {
                last = e
            }
            Thread.sleep(1_000)
        }
        throw IllegalStateException("Keycloak at $baseUrl did not become ready", last)
    }

    fun adminToken(): String =
        form(
            "/realms/master/protocol/openid-connect/token",
            mapOf(
                "client_id" to "admin-cli",
                "username" to ADMIN_USER,
                "password" to ADMIN_PASSWORD,
                "grant_type" to "password",
            ),
        ).let { Json.read(it.body()).path("access_token").asText() }

    /** Creates a realm with a confidential client whose service account we can get tokens for. */
    fun createRealm(realm: String, token: String = adminToken()) {
        admin("POST", "/admin/realms", token, """{"realm":"$realm","enabled":true}""")
        admin(
            "POST", "/admin/realms/$realm/clients", token,
            """{"clientId":"$TEST_CLIENT","enabled":true,"publicClient":false,
                "serviceAccountsEnabled":true,"standardFlowEnabled":false,
                "secret":"$TEST_CLIENT_SECRET"}""",
        )
    }

    fun deleteRealm(realm: String, token: String = adminToken()) {
        runCatching { admin("DELETE", "/admin/realms/$realm", token) }
    }

    /**
     * A token issued by [realm], and therefore signed with whatever key that realm has
     * active for its default signature algorithm. This is the assertion surface: if the
     * extension works, this token carries a NetHSM `kid`.
     */
    fun serviceAccountToken(realm: String): HttpResponse<String> = form(
        "/realms/$realm/protocol/openid-connect/token",
        mapOf(
            "client_id" to TEST_CLIENT,
            "client_secret" to TEST_CLIENT_SECRET,
            "grant_type" to "client_credentials",
        ),
    )

    fun setDefaultSignatureAlgorithm(realm: String, algorithm: String, token: String = adminToken()) {
        admin(
            "PUT", "/admin/realms/$realm", token,
            """{"realm":"$realm","defaultSignatureAlgorithm":"$algorithm"}""",
        )
    }

    /** Registers a `nethsm` key provider. parentId is omitted: Keycloak defaults it to the realm. */
    fun registerNetHsmProvider(
        realm: String,
        name: String,
        keyPrefix: String,
        algorithm: String,
        priority: Int = 200,
        token: String = adminToken(),
    ): HttpResponse<String> = admin(
        "POST", "/admin/realms/$realm/components", token,
        """{"name":"$name","providerId":"nethsm","providerType":"org.keycloak.keys.KeyProvider",
            "config":{"priority":["$priority"],"enabled":["true"],"active":["true"],
                      "keyPrefix":["$keyPrefix"],"algorithm":["$algorithm"]}}""",
        expectSuccess = false,
    )

    fun realmKeys(realm: String, token: String = adminToken()): HttpResponse<String> =
        admin("GET", "/admin/realms/$realm/keys", token, expectSuccess = false)

    fun jwks(realm: String): JsonNode =
        Json.read(get("/realms/$realm/protocol/openid-connect/certs").body())

    fun jwk(realm: String, kid: String): JsonNode =
        jwks(realm).path("keys").first { it.path("kid").asText() == kid }

    private fun get(path: String): HttpResponse<String> = http.send(
        HttpRequest.newBuilder(URI.create(baseUrl + path)).GET().build(),
        HttpResponse.BodyHandlers.ofString(),
    )

    private fun form(path: String, fields: Map<String, String>): HttpResponse<String> {
        val body = fields.entries.joinToString("&") { (k, v) -> "$k=$v" }
        val response = http.send(
            HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
        return response
    }

    private fun admin(
        method: String,
        path: String,
        token: String,
        body: String? = null,
        expectSuccess: Boolean = true,
    ): HttpResponse<String> {
        val publisher = body?.let { HttpRequest.BodyPublishers.ofString(it) }
            ?: HttpRequest.BodyPublishers.noBody()
        val response = http.send(
            HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer $token")
                .header("Content-Type", "application/json")
                .method(method, publisher)
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
        if (expectSuccess && response.statusCode() >= 300) {
            error("$method $path -> ${response.statusCode()}: ${response.body()}")
        }
        return response
    }

    companion object {
        const val BASE_URL = "http://localhost:8080"
        const val ADMIN_USER = "admin"
        const val ADMIN_PASSWORD = "admin"
        const val TEST_CLIENT = "it-client"
        const val TEST_CLIENT_SECRET = "it-secret"
    }
}
