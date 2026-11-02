package com.nitrokey.nethsm.keycloak.client

import com.nitrokey.nethsm.keycloak.CryptoConst
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

/**
 * Accepts a NetHSM certificate only if its SHA-256 fingerprint is one of [pins].
 *
 * Pinning replaces CA validation rather than supplementing it, because a NetHSM
 * certificate is typically self-signed. That makes this the only thing standing between
 * the Operator credential and whatever answers on the configured address, so it is kept
 * out of [NetHsmClient] and tested directly: a trust manager that quietly stopped
 * rejecting would leave every happy path working and nothing looking wrong.
 */
internal class FingerprintTrustManager(private val pins: Set<String>) : X509TrustManager {

    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String): Unit =
        throw UnsupportedOperationException("client authentication is not used")

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        val leaf = chain.firstOrNull() ?: throw CertificateException("empty certificate chain")
        val actual = fingerprintOf(leaf)
        if (actual !in pins) {
            // Naming the fingerprint actually presented is what lets an operator pin it.
            throw CertificateException("NetHSM certificate fingerprint $actual is not pinned")
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()

    companion object {
        /** Lowercase hex SHA-256 of the certificate, the form `tls-fingerprints` expects. */
        fun fingerprintOf(certificate: X509Certificate): String =
            MessageDigest.getInstance(CryptoConst.TYPE_SHA_256)
                .digest(certificate.encoded)
                .joinToString("") { "%02x".format(it) }
    }
}

/** Development only, for the self-signed certificate the NetHSM test container serves. */
internal object TrustAnything : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
