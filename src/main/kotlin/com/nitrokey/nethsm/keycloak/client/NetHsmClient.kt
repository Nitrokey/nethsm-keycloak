package com.nitrokey.nethsm.keycloak.client

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.NullNode
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
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext

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
class NetHsmClient(private val config: NetHsmConfig) : Closeable, KeySource, CekDecryptor, MessageSigner {

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

    /**
     * `GET /health/ready` -- 200 when NetHSM is Operational, 412 when it is Locked or
     * still booting. Unauthenticated, and used only for a startup log line.
     */
    fun ready(): Boolean = try {
        request(HttpGet("/health/ready"))
        true
    } catch (e: Exception) {
        log.debugf(e, "NetHSM readiness probe failed")
        false
    }

    /** `GET /keys/{prefix}*` -- ids only, so callers follow up with [key] per id. */
    override fun keyIds(prefix: String): List<String> =
        request(HttpGet("/keys/${encode(prefix)}*")).mapNotNull { it.path("id").asText(null) }

    /** `GET /keys/{id}` -- type, mechanisms and public key in one response. */
    override fun key(id: String): NetHsmKey? {
        val key = NetHsmKey.parse(id, request(HttpGet("/keys/${encode(id)}"))) ?: return null
        // Fetched here rather than lazily from the KeyWrapper: discovery caches the
        // result, so this costs one call per key per refresh instead of one per request.
        return key.withCertificate(certificate(id))
    }

    /**
     * `POST /keys/{id}/sign`. [message] is whatever the mode expects: a DigestInfo-prefixed
     * digest for `PKCS1`, a bare digest for `PSS_*` and `ECDSA`, the raw message for `EdDSA`.
     */
    override fun sign(keyId: String, mode: String, message: ByteArray): ByteArray {
        val body = JsonSerialization.mapper.createObjectNode()
            .put("mode", mode)
            .put("message", Base64.getEncoder().encodeToString(message))
        val post = HttpPost("/keys/${encode(keyId)}/sign").apply {
            entity = ByteArrayEntity(JsonSerialization.mapper.writeValueAsBytes(body), ContentType.APPLICATION_JSON)
        }
        val signature = request(post).path("signature").asText(null)
            ?: throw NetHsmRequestException(200, "sign response for '$keyId' had no signature")
        return Base64.getDecoder().decode(signature)
    }

    /**
     * `POST /keys/{id}/decrypt`. Used to unwrap a JWE content encryption key.
     *
     * The ciphertext here comes from whoever posted the JWE, so this is an RSA
     * decryption oracle by construction. Callers must not distinguish a padding failure
     * from any other failure -- see NetHsmCipherSpi.
     */
    override fun decryptCek(keyId: String, mode: String, ciphertext: ByteArray): ByteArray {
        val body = JsonSerialization.mapper.createObjectNode()
            .put("mode", mode)
            .put("encrypted", Base64.getEncoder().encodeToString(ciphertext))
        val post = HttpPost("/keys/${encode(keyId)}/decrypt").apply {
            entity = ByteArrayEntity(JsonSerialization.mapper.writeValueAsBytes(body), ContentType.APPLICATION_JSON)
        }
        val decrypted = request(post).path("decrypted").asText(null)
            ?: throw NetHsmRequestException(200, "decrypt response for '$keyId' had no payload")
        return Base64.getDecoder().decode(decrypted)
    }

    /**
     * `GET /keys/{id}/cert` -- the certificate NetHSM stores alongside a key, as DER, or
     * null when there is none.
     *
     * SAML needs this and JWS does not: XML-DSig is handed the certificate to place in
     * `KeyInfo`, and a peer that validates against the IdP descriptor expects to find it
     * there. NetHSM stores whatever bytes were uploaded, so pairing the certificate with
     * the key is the operator's business, not something to re-derive here.
     */
    fun certificate(id: String): X509Certificate? {
        val get = HttpGet("/keys/${encode(id)}/cert").apply {
            setHeader("Accept", "application/octet-stream")
        }
        val der = try {
            requestBytes(get)
        } catch (e: NetHsmRequestException) {
            // 404 is the ordinary case: no certificate was ever uploaded. Anything else
            // is a misconfiguration, and saying so matters -- treating every refusal as
            // "no certificate" is what hid an Accept-header bug during development. Null
            // either way, because a certificate is optional and a realm that only signs
            // JWTs must not lose its keys over one.
            if (e.status == 404) {
                log.debugf("NetHSM key '%s' has no certificate", id)
            } else {
                log.warnf(
                    e,
                    "NetHSM refused the certificate for key '%s' with HTTP %d; SAML would have none",
                    id, e.status,
                )
            }
            return null
        } ?: return null

        return try {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(der.inputStream()) as X509Certificate
        } catch (e: Exception) {
            log.warnf(e, "NetHSM key '%s' has a stored certificate that is not X.509, ignoring it", id)
            null
        }
    }

    private fun request(request: HttpRequestBase): JsonNode {
        val body = requestBytes(request)
        // The health endpoints answer 200 with no body, hence the NullNode.
        return if (body == null || body.isEmpty()) {
            NullNode.instance
        } else {
            JsonSerialization.mapper.readTree(body)
        }
    }

    /**
     * Tries each configured URL in turn, [NetHsmConfig.retries] times over. Only
     * transport failures, 412 and 5xx are retried; any other 4xx is a real answer and
     * repeating it just delays the error.
     *
     * Returns the raw body, because not every endpoint answers with JSON -- the
     * certificate one returns DER.
     */
    private fun requestBytes(request: HttpRequestBase): ByteArray? {
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

    private fun send(request: HttpRequestBase, base: String, path: String): ByteArray? {
        request.uri = java.net.URI.create(base.trimEnd('/') + path)
        request.setHeader("Authorization", authorization)
        // Only when the caller has not asked for something else. The certificate endpoint
        // serves DER and answers 406 to application/json.
        if (request.getFirstHeader("Accept") == null) {
            request.setHeader("Accept", "application/json")
        }

        return http.execute(request).use { response ->
            val status = response.statusLine.statusCode
            val body = response.entity?.let { EntityUtils.toByteArray(it) }
            when {
                status in 200..299 -> body
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
}
