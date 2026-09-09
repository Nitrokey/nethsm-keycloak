package com.nitrokey.nethsm.keycloak.support

import com.nitrokey.nethsm.keycloak.client.KeyDiscovery
import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.client.NetHsmConnection
import com.nitrokey.nethsm.keycloak.client.NetHsmConfig
import java.time.Duration

/**
 * The NetHSM side of the testbed.
 *
 * Every test class waits for NetHSM to be Operational before it starts, because
 * `FailClosedIT` deliberately stops the container and a restarted NetHSM needs a moment
 * to come back. Without this, whichever class ran next would fail for reasons that have
 * nothing to do with what it is testing.
 */
object NetHsm {

    const val URL = "https://localhost:8443/api/v1"
    const val OPERATOR_USER = "keycloak"
    const val OPERATOR_PASSPHRASE = "KeycloakKeycloak"

    // Only for fixtures that have to act as an Administrator. The extension itself never
    // uses these: uploading a certificate, like generating a key, is done out of band.
    private const val ADMIN_USER = "admin"
    private const val ADMIN_PASSPHRASE = "AdminAdminAdmin"

    fun client(): NetHsmClient = clientFor(listOf(URL))

    /**
     * A connection with discovery that never caches, so a test sees each change to NetHSM
     * immediately rather than through a ttl.
     */
    fun connection(): NetHsmConnection = client().let { client ->
        NetHsmConnection(
            client,
            KeyDiscovery(client, Duration.ZERO, NetHsmConfig.OnUnavailable.FAIL),
        )
    }

    /** A client over an explicit endpoint list, for exercising round-robin and failover. */
    fun clientFor(urls: List<String>): NetHsmClient = NetHsmClient(
        NetHsmConfig(
            urls = urls,
            username = OPERATOR_USER,
            passphrase = OPERATOR_PASSPHRASE,
            tlsFingerprints = emptySet(),
            // The test image serves a self-signed certificate.
            tlsInsecure = true,
            timeout = Duration.ofSeconds(5),
            retries = 0,
            retryDelay = Duration.ofMillis(200),
            maxConnections = 4,
            onUnavailable = NetHsmConfig.OnUnavailable.FAIL,
            discoveryCache = Duration.ZERO,
        ),
    )

    /** Restarts the container and blocks until NetHSM is Operational again. */
    fun restart() {
        Compose.start("nethsm")
        awaitOperational()
    }

    /**
     * Short by design. NetHSM boots in seconds, so a longer wait only turns a real
     * failure into what looks like a hung run -- once per test class.
     */
    fun awaitOperational(timeout: Duration = Duration.ofSeconds(45)) {
        client().use { client ->
            val deadline = System.nanoTime() + timeout.toNanos()
            while (System.nanoTime() < deadline) {
                if (client.ready()) return
                Thread.sleep(1_000)
            }
            error(
                "NetHSM at $URL did not become Operational within $timeout. State: ${state()}. " +
                    "'Unprovisioned' after a restart means /data is not on a volume; 'Locked' " +
                    "means provision.sh did not enable unattended boot.",
            )
        }
    }

    /**
     * `PUT /keys/{id}/cert` with an Administrator credential, which is how an operator
     * would supply one. NetHSM wants raw DER under application/octet-stream; PEM is
     * rejected with 415.
     */
    fun storeCertificate(keyId: String, der: ByteArray) {
        val connection = open("$URL/keys/$keyId/cert").apply {
            requestMethod = "PUT"
            doOutput = true
            setRequestProperty("Content-Type", "application/octet-stream")
            setRequestProperty(
                "Authorization",
                "Basic " + java.util.Base64.getEncoder()
                    .encodeToString("$ADMIN_USER:$ADMIN_PASSPHRASE".toByteArray()),
            )
        }
        connection.outputStream.use { it.write(der) }
        val status = connection.responseCode
        // 409 means one is already stored, which is fine for a fixture that may re-run.
        check(status == 201 || status == 200 || status == 409) {
            "storing a certificate for '$keyId' returned $status"
        }
    }

    private fun open(url: String) =
        (java.net.URI.create(url).toURL().openConnection() as javax.net.ssl.HttpsURLConnection).apply {
            hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            sslSocketFactory = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(TrustAnything), java.security.SecureRandom())
            }.socketFactory
            connectTimeout = 5_000
            readTimeout = 5_000
        }

    /** Reads /health/state directly, purely to make the failure message actionable. */
    private fun state(): String = runCatching {
        val connection = (java.net.URI.create("$URL/health/state").toURL().openConnection()
            as javax.net.ssl.HttpsURLConnection).apply {
            hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            sslSocketFactory = javax.net.ssl.SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(TrustAnything), java.security.SecureRandom())
            }.socketFactory
            connectTimeout = 3_000
            readTimeout = 3_000
        }
        connection.inputStream.bufferedReader().readText()
    }.getOrElse { "unreachable (${it.javaClass.simpleName})" }

    private object TrustAnything : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>, a: String) = Unit
        override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>, a: String) = Unit
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
    }
}
