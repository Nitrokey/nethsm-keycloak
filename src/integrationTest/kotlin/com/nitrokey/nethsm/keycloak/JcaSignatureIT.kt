package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.jca.NetHsmSecurityProvider
import com.nitrokey.nethsm.keycloak.support.NetHsm
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.w3c.dom.Document
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import javax.xml.crypto.dsig.CanonicalizationMethod
import javax.xml.crypto.dsig.DigestMethod
import javax.xml.crypto.dsig.SignatureMethod
import javax.xml.crypto.dsig.Transform
import javax.xml.crypto.dsig.XMLSignature
import javax.xml.crypto.dsig.XMLSignatureFactory
import javax.xml.crypto.dsig.dom.DOMSignContext
import javax.xml.crypto.dsig.dom.DOMValidateContext
import javax.xml.crypto.dsig.keyinfo.KeyInfo
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec
import javax.xml.crypto.dsig.spec.TransformParameterSpec
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Signing through plain JCA, which is the path SAML takes.
 *
 * `SamlProtocol` pulls `KeyWrapper.getPrivateKey()` and hands the bare
 * `java.security.PrivateKey` to XML-DSig; nothing about `SignatureProvider` is involved,
 * so the ten JOSE algorithms this extension registers do not help there. Until the JCA
 * provider offered a `Signature` service this failed with "No installed provider supports
 * this key", and a realm serving SAML clients could not sign an assertion with an HSM key.
 *
 * The second test is the one that settles it: it signs a document with the real
 * `XMLSignatureFactory` Keycloak uses, then validates the result against the public key.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JcaSignatureIT {

    private lateinit var client: NetHsmClient

    @BeforeAll
    fun setUp() {
        NetHsm.awaitOperational()
        client = NetHsm.client()
        NetHsmSecurityProvider.install()
    }

    @AfterAll
    fun tearDown() = client.close()

    private fun handleFor(keyId: String, jcaAlgorithm: String) =
        NetHsmPrivateKeyHandle(keyId, jcaAlgorithm, signer = client)

    /**
     * Every algorithm SAML can ask for, plus the EC and Ed25519 ones, signed in the HSM
     * and verified locally. A wrong DigestInfo header or a bare-versus-prefixed mix-up
     * yields a signature that is the right length and simply does not verify, so the
     * verification is the assertion that matters.
     */
    @Test
    fun `signatures produced in NetHSM verify against the public key`() {
        val message = "the quick brown fox".toByteArray()

        // PSS is verified through RSASSA-PSS with explicit parameters, not through the
        // SHA*withRSAandMGF1 name: the JDK has no such algorithm, and now that this
        // provider registers it for signing it would be the only one offering it -- and
        // it deliberately refuses to verify, which is the platform's job.
        listOf(
            Case("SHA1withRSA", "kc-rsa-pkcs1", "RSA"),
            Case("SHA256withRSA", "kc-rsa-pkcs1", "RSA"),
            Case("SHA384withRSA", "kc-rsa-pkcs1", "RSA"),
            Case("SHA512withRSA", "kc-rsa-pkcs1", "RSA"),
            Case("SHA256withRSAandMGF1", "kc-rsa-pss", "RSA", pss = "SHA-256"),
            Case("SHA384withRSAandMGF1", "kc-rsa-pss", "RSA", pss = "SHA-384"),
            Case("SHA512withRSAandMGF1", "kc-rsa-pss", "RSA", pss = "SHA-512"),
            Case("SHA256withECDSA", "kc-ec-p256", "EC"),
            Case("SHA384withECDSA", "kc-ec-p384", "EC"),
            Case("SHA512withECDSA", "kc-ec-p521", "EC"),
            Case("Ed25519", "kc-ed25519", "Ed25519"),
        ).forEach { case ->
            val key = assertNotNull(client.key(case.keyId), "testbed key ${case.keyId} is missing")

            val signature = Signature.getInstance(case.signAlgorithm).run {
                initSign(handleFor(case.keyId, case.jcaAlgorithm))
                update(message)
                sign()
            }

            val verifier = if (case.pss != null) {
                Signature.getInstance("RSASSA-PSS").apply {
                    val digestLength = java.security.MessageDigest.getInstance(case.pss).digestLength
                    setParameter(PSSParameterSpec(case.pss, "MGF1", MGF1ParameterSpec(case.pss), digestLength, 1))
                }
            } else {
                Signature.getInstance(case.signAlgorithm)
            }
            verifier.initVerify(key.publicKey)
            verifier.update(message)

            assertTrue(verifier.verify(signature), "${case.signAlgorithm} signed in NetHSM did not verify")
        }
    }

    private data class Case(
        val signAlgorithm: String,
        val keyId: String,
        val jcaAlgorithm: String,
        /** Digest name when the signature has to be verified as RSASSA-PSS. */
        val pss: String? = null,
    )

    /**
     * The SAML path itself. `XMLSignatureFactory` is what `XMLSignatureUtil` drives, and
     * it reaches the key only through `java.security.Signature`.
     */
    @Test
    fun `XML-DSig can sign a document with an HSM-held key`() {
        val keyId = "kc-rsa-pkcs1"
        val key = assertNotNull(client.key(keyId))

        val document = assertionLikeDocument()
        val root = document.documentElement
        val factory = XMLSignatureFactory.getInstance("DOM")

        val reference = factory.newReference(
            "",
            factory.newDigestMethod(DigestMethod.SHA256, null),
            listOf(factory.newTransform(Transform.ENVELOPED, null as TransformParameterSpec?)),
            null,
            null,
        )
        val signedInfo = factory.newSignedInfo(
            factory.newCanonicalizationMethod(
                CanonicalizationMethod.EXCLUSIVE,
                null as C14NMethodParameterSpec?,
            ),
            factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
            listOf(reference),
        )
        val keyInfo: KeyInfo = factory.keyInfoFactory.let { kif ->
            kif.newKeyInfo(listOf(kif.newKeyValue(key.publicKey)))
        }

        // The private key here is the opaque handle: no material, only a reference.
        factory.newXMLSignature(signedInfo, keyInfo)
            .sign(DOMSignContext(handleFor(keyId, "RSA"), root))

        val signatureNode = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0)
        assertNotNull(signatureNode, "no Signature element was produced")

        val validateContext = DOMValidateContext(key.publicKey, signatureNode)
        val unmarshalled = factory.unmarshalXMLSignature(validateContext)
        assertTrue(
            unmarshalled.validate(validateContext),
            "the XML signature produced by NetHSM did not validate, which is what SAML would do",
        )
    }

    private fun assertionLikeDocument(): Document {
        val document = DocumentBuilderFactory.newInstance()
            .apply { isNamespaceAware = true }
            .newDocumentBuilder()
            .newDocument()
        val assertion = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
        assertion.setAttribute("ID", "_test")
        assertion.appendChild(document.createTextNode("nethsm"))
        document.appendChild(assertion)
        return document
    }
}
