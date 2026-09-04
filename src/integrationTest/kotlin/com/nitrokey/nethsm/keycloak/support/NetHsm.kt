package com.nitrokey.nethsm.keycloak.support

import com.nitrokey.nethsm.keycloak.client.NetHsmClient
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

    fun client(): NetHsmClient = clientFor(listOf(URL))

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
