package com.nitrokey.nethsm.keycloak.client

import com.fasterxml.jackson.databind.JsonNode
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpRequestBase
import org.apache.http.conn.ssl.DefaultHostnameVerifier
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.entity.ContentType
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import org.jboss.logging.Logger
import org.keycloak.util.JsonSerialization
import java.io.Closeable
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/** NetHSM unreachable, or reachable but not in the Operational state. Retryable. */
class NetHsmUnavailableException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/** NetHSM answered and rejected the request. Not retryable. */
class NetHsmRequestException(val status: Int, message: String) : RuntimeException(message)

/**
 * Thin client over the handful of NetHSM endpoints this extension needs.
 *
 * One instance is held for the lifetime of the provider factory, over a bounded
 * connection pool. That matters: the comparable Crypki extension builds a fresh client,
 * and so a fresh TLS handshake, inside every `sign()` call, which discards the
 * connection reuse NetHSM's published throughput figures assume.
 *
 * Apache HttpClient rather than `java.net.http` because the latter forces hostname
 * verification regardless of the `SSLParameters` it is given, which makes certificate
 * pinning against a self-signed NetHSM certificate impossible without setting a
 * JVM-wide system property.
 */
class NetHsmClient(private val config: NetHsmConfig) : Closeable {

    private val log = Logger.getLogger(NetHsmClient::class.java)
    private val cursor = AtomicInteger(0)

    private val authorization = "Basic " + Base64.getEncoder()
        .encodeToString("${config.username}:${config.passphrase}".toByteArray())

    private val http: CloseableHttpClient = HttpClients.custom()
        .setSSLSocketFactory(socketFactory())
        .setMaxConnTotal(config.maxConnections)
        .setMaxConnPerRoute(config.maxConnections)
        .setDefaultRequestConfig(
            RequestConfig.custom()
                // Connect is bounded separately, and tightly: it is the one that a
                // NetHSM dropping packets makes the caller wait out on every attempt,
                // on a Keycloak request thread. Socket and pool waits are governed by
                // the full timeout, since by then someone is actually answering.
                .setConnectTimeout(config.connectTimeout.toMillis().toInt())
                .setSocketTimeout(config.timeout.toMillis().toInt())
                .setConnectionRequestTimeout(config.timeout.toMillis().toInt())
                .build(),
        )
        .build()

    /** `GET /keys/{prefix}*` -- ids only, so callers follow up with [key] per id. */
    fun keyIds(prefix: String): List<String> =
        request(HttpGet("/keys/${encode(prefix)}*")).mapNotNull { it.path("id").asText(null) }

    /** `GET /keys/{id}` -- type, mechanisms and public key in one response. */
    fun key(id: String): NetHsmKey? = NetHsmKey.parse(id, request(HttpGet("/keys/${encode(id)}")))

    /**
     * `POST /keys/{id}/sign`. [message] is whatever the mode expects: a DigestInfo-prefixed
     * digest for `PKCS1`, a bare digest for `PSS_*` and `ECDSA`, the raw message for `EdDSA`.
     */
    fun sign(id: String, mode: String, message: ByteArray): ByteArray {
        val body = JsonSerialization.mapper.createObjectNode()
            .put("mode", mode)
            .put("message", Base64.getEncoder().encodeToString(message))
        val post = HttpPost("/keys/${encode(id)}/sign").apply {
            entity = ByteArrayEntity(JsonSerialization.mapper.writeValueAsBytes(body), ContentType.APPLICATION_JSON)
        }
        val signature = request(post).path("signature").asText(null)
            ?: throw NetHsmRequestException(200, "sign response for '$id' had no signature")
        return Base64.getDecoder().decode(signature)
    }

    /**
     * Tries each configured URL in turn, [NetHsmConfig.retries] times over. Only
     * transport failures, 412 and 5xx are retried; any other 4xx is a real answer and
     * repeating it just delays the error.
     */
    private fun request(request: HttpRequestBase): JsonNode {
        val path = request.uri.toString()
        var last: Exception? = null
        val attempts = (config.retries + 1) * config.urls.size

        repeat(attempts) { attempt ->
            val base = config.urls[cursor.getAndIncrement().mod(config.urls.size)]
            try {
                return send(request, base, path)
            } catch (e: NetHsmRequestException) {
                throw e
            } catch (e: Exception) {
                last = e
                log.debugf(e, "NetHSM %s %s failed on %s (attempt %d/%d)", request.method, path, base, attempt + 1, attempts)
                if (attempt < attempts - 1) Thread.sleep(config.retryDelay.toMillis())
            }
        }
        throw NetHsmUnavailableException("NetHSM unreachable after $attempts attempts: ${request.method} $path", last)
    }

    private fun send(request: HttpRequestBase, base: String, path: String): JsonNode {
        request.uri = java.net.URI.create(base.trimEnd('/') + path)
        request.setHeader("Authorization", authorization)
        request.setHeader("Accept", "application/json")

        return http.execute(request).use { response ->
            val status = response.statusLine.statusCode
            val body = response.entity?.let { EntityUtils.toByteArray(it) }
            when {
                status in 200..299 -> JsonSerialization.mapper.readTree(body)
                // 412 is NetHSM's "not Operational" -- locked or still booting.
                status == 412 || status >= 500 ->
                    throw NetHsmUnavailableException("${request.method} $path returned $status")
                else -> throw NetHsmRequestException(status, "${request.method} $path returned $status")
            }
        }
    }

    private fun socketFactory(): SSLConnectionSocketFactory {
        val verifier = if (config.tlsInsecure || config.tlsFingerprints.isNotEmpty()) {
            // Pinning replaces both CA validation and hostname verification: a pinned
            // NetHSM certificate is usually self-signed with a CN that does not match
            // how Keycloak addresses it, and the fingerprint is the stronger assertion.
            NoopHostnameVerifier.INSTANCE
        } else {
            DefaultHostnameVerifier()
        }
        return SSLConnectionSocketFactory(sslContext(), verifier)
    }

    private fun sslContext(): SSLContext {
        val trustManager = when {
            config.tlsInsecure -> {
                log.warn("NetHSM TLS verification is disabled (tls-insecure). Do not use in production.")
                TrustAnything
            }
            config.tlsFingerprints.isNotEmpty() -> FingerprintTrustManager(config.tlsFingerprints)
            else -> return SSLContext.getDefault()
        }
        return SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManager), SecureRandom())
        }
    }

    private fun encode(segment: String) = segment.replace("/", "%2F")

    override fun close() {
        http.close()
    }

    private object TrustAnything : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private class FingerprintTrustManager(private val pins: Set<String>) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String): Unit =
            throw UnsupportedOperationException("client authentication is not used")

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val leaf = chain.firstOrNull()
                ?: throw java.security.cert.CertificateException("empty certificate chain")
            val actual = MessageDigest.getInstance("SHA-256")
                .digest(leaf.encoded)
                .joinToString("") { "%02x".format(it) }
            if (actual !in pins) {
                throw java.security.cert.CertificateException(
                    "NetHSM certificate fingerprint $actual is not pinned",
                )
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
