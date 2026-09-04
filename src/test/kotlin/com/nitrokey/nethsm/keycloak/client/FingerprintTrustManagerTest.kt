package com.nitrokey.nethsm.keycloak.client

import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Pinning replaces CA validation rather than supplementing it, so this trust manager is
 * the only thing between the NetHSM Operator credential and whatever answers on the
 * configured address.
 *
 * The negative cases carry the value. A trust manager that stopped rejecting would leave
 * every happy path working and nothing looking wrong -- the failure that survives manual
 * testing, because manual testing checks that the right certificate works.
 *
 * The certificates are throwaway fixtures under src/test/resources/certs; only their
 * public halves are here, and nothing ever uses them for a TLS handshake.
 */
class FingerprintTrustManagerTest {

    private val leaf = load("leaf.pem")
    private val issuer = load("issuer.pem")
    private val leafPin = FingerprintTrustManager.fingerprintOf(leaf)

    @Test
    fun `a certificate whose fingerprint is pinned is accepted`() {
        FingerprintTrustManager(setOf(leafPin)).checkServerTrusted(arrayOf(leaf), "RSA")
    }

    @Test
    fun `a certificate that is not pinned is rejected`() {
        val failure = assertFailsWith<CertificateException> {
            FingerprintTrustManager(setOf("0".repeat(64))).checkServerTrusted(arrayOf(leaf), "RSA")
        }
        assertTrue(
            leafPin in failure.message.orEmpty(),
            "must name the fingerprint presented, so an operator can pin it: ${failure.message}",
        )
    }

    @Test
    fun `one matching pin among several is enough`() {
        FingerprintTrustManager(setOf("a".repeat(64), leafPin, "b".repeat(64)))
            .checkServerTrusted(arrayOf(leaf), "RSA")
    }

    /** Fails closed: no pins must mean nothing is trusted, never everything. */
    @Test
    fun `an empty pin set rejects everything`() {
        assertFailsWith<CertificateException> {
            FingerprintTrustManager(emptySet()).checkServerTrusted(arrayOf(leaf), "RSA")
        }
    }

    @Test
    fun `an empty chain is rejected`() {
        assertFailsWith<CertificateException> {
            FingerprintTrustManager(setOf(leafPin)).checkServerTrusted(emptyArray(), "RSA")
        }
    }

    /**
     * Only the leaf is pinned. Trusting a chain because something further up matches
     * would let any certificate that issuer signed through, which is the property
     * pinning exists to remove.
     */
    @Test
    fun `a pinned certificate deeper in the chain does not vouch for the leaf`() {
        assertFailsWith<CertificateException> {
            FingerprintTrustManager(setOf(FingerprintTrustManager.fingerprintOf(issuer)))
                .checkServerTrusted(arrayOf(leaf, issuer), "RSA")
        }
    }

    @Test
    fun `client authentication is refused rather than silently accepted`() {
        assertFailsWith<UnsupportedOperationException> {
            FingerprintTrustManager(setOf(leafPin)).checkClientTrusted(arrayOf(leaf), "RSA")
        }
    }

    @Test
    fun `no issuers are advertised, since pinning does not delegate to a CA`() {
        assertEquals(0, FingerprintTrustManager(setOf(leafPin)).acceptedIssuers.size)
    }

    /** The form `openssl x509 -fingerprint -sha256` prints, once colons are stripped. */
    @Test
    fun `the fingerprint is lowercase hex SHA-256`() {
        assertTrue(Regex("^[0-9a-f]{64}$").matches(leafPin), leafPin)
    }

    private fun load(name: String): X509Certificate =
        javaClass.getResourceAsStream("/certs/$name").use {
            CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
        }
}
