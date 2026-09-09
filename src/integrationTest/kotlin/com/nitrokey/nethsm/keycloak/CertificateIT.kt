package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The certificate NetHSM stores for a key, which only SAML needs.
 *
 * XML-DSig is handed the certificate to place in `KeyInfo`, and a SAML peer validating
 * against the IdP descriptor expects to find it there, so a key with no certificate is
 * usable for JWS but incomplete for SAML.
 *
 * The fixture issues a certificate over the *HSM key's own public key*, signed by a
 * throwaway CA, which is what an operator would end up with after signing the CSR from
 * `POST /keys/{id}/csr.pem`. That makes the assertion worth something: the certificate
 * that comes back has to carry the same public key as the key it belongs to, which a
 * mangled fetch or a wrong parse would not.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CertificateIT {

    private lateinit var client: NetHsmClient

    /** No certificate is uploaded for this one, so it covers the ordinary case. */
    private val withoutCertificate = "kc-rsa-pss"
    private val withCertificate = "kc-ec-p256"

    @BeforeAll
    fun setUp() {
        NetHsm.awaitOperational()
        client = NetHsm.client()

        val key = assertNotNull(client.key(withCertificate), "testbed key $withCertificate is missing")
        NetHsm.storeCertificate(withCertificate, issueCertificate(key.publicKey).encoded)
    }

    @AfterAll
    fun tearDown() = client.close()

    @Test
    fun `a stored certificate is fetched and carries the key's own public key`() {
        val certificate = assertNotNull(
            client.certificate(withCertificate),
            "the certificate stored for $withCertificate was not returned",
        )

        val key = assertNotNull(client.key(withCertificate))
        assertEquals(
            key.publicKey,
            certificate.publicKey,
            "the certificate does not carry the public key of the key it belongs to",
        )
        assertEquals(X500Principal("CN=$withCertificate"), certificate.subjectX500Principal)
    }

    /** A key without one must stay perfectly usable: JWS never asks for a certificate. */
    @Test
    fun `a key with no certificate reports none instead of failing`() {
        assertNull(client.certificate(withoutCertificate))
        assertNotNull(client.key(withoutCertificate), "discovery must still work without a certificate")
    }

    @Test
    fun `the key read attaches the certificate, so discovery caches it with the metadata`() {
        assertNotNull(client.key(withCertificate)?.certificate, "key() should carry the certificate")
        assertNull(client.key(withoutCertificate)?.certificate)
    }

    /**
     * What Keycloak actually consumes. `SamlProtocol` passes `KeyWrapper.getCertificate()`
     * into `signWith`, so the certificate has to survive as far as the wrapper.
     */
    @Test
    fun `the published key wrapper carries the certificate`() {
        val wrapper = NetHsmKeyProvider(
            componentModel(prefix = withCertificate, algorithm = "ES256"),
            NetHsm.connection(),
        ).getKeysStream().toList().single()

        assertEquals(withCertificate, wrapper.kid)
        val certificate = assertNotNull(wrapper.certificate, "the wrapper SAML signs with has no certificate")
        assertEquals(wrapper.publicKey, certificate.publicKey)
    }

    private fun componentModel(prefix: String, algorithm: String) =
        org.keycloak.component.ComponentModel().apply {
            id = "certificate-it"
            config = org.keycloak.common.util.MultivaluedHashMap<String, String>().apply {
                putSingle("keyPrefix", prefix)
                putSingle("algorithm", algorithm)
            }
        }

    /** A throwaway CA issuing over the HSM key's public key; the CA key is never stored. */
    private fun issueCertificate(subjectKey: PublicKey): X509Certificate {
        val ca = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            X500Principal("CN=NetHSM Test CA"),
            BigInteger.valueOf(now),
            Date(now - 60_000),
            Date(now + 3_600_000),
            X500Principal("CN=$withCertificate"),
            subjectKey,
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(ca.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }
}
