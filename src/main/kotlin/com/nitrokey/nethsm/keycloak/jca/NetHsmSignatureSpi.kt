package com.nitrokey.nethsm.keycloak.jca

import com.nitrokey.nethsm.keycloak.CryptoConst
import com.nitrokey.nethsm.keycloak.NetHsmAlgorithms
import com.nitrokey.nethsm.keycloak.NetHsmPrivateKeyHandle
import com.nitrokey.nethsm.keycloak.client.MessageSigner
import java.io.ByteArrayOutputStream
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SignatureException
import java.security.SignatureSpi
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/**
 * Signing performed inside NetHSM, exposed as a JCA [SignatureSpi].
 *
 * This exists for the callers that never see a Keycloak `KeyWrapper`. SAML is the one that
 * matters: `SamlProtocol` takes `KeyWrapper.getPrivateKey()` and hands the bare
 * `java.security.PrivateKey` to XML-DSig, which signs through `java.security.Signature`.
 * That path bypasses `SignatureProvider` entirely, so without this the HSM is not involved
 * and signing an assertion fails with "No installed provider supports this key".
 *
 * Every key that is not a NetHSM handle is rejected with [InvalidKeyException], which is
 * how JCA is told to move on. Combined with registering the provider last, ordinary RSA
 * and EC keys keep using the platform implementation.
 *
 * @param digest JCA digest name to apply before sending, or null when the mode signs the
 *   message itself. Ed25519 derives its nonce from its own hash of the message, so
 *   pre-hashing would sign the wrong value.
 * @param mode NetHSM `SignMode`.
 * @param prefixDigestInfo whether to prepend the RFC 8017 DigestInfo header. `PKCS1` signs
 *   the submitted bytes verbatim, so EMSA-PKCS1-v1_5 needs it; `PSS_*` and `ECDSA` take a
 *   bare digest.
 */
abstract class NetHsmSignatureSpi(
    private val digest: String?,
    private val mode: String,
    private val prefixDigestInfo: Boolean,
) : SignatureSpi() {

    private var keyId: String? = null
    private var signer: MessageSigner? = null

    /** Only one of these is ever used: a digest for everything except Ed25519. */
    private val md: MessageDigest? = digest?.let { MessageDigest.getInstance(it) }
    private val raw = ByteArrayOutputStream()

    override fun engineInitSign(privateKey: PrivateKey?) {
        // Cleared first: a rejected init must leave nothing usable behind, or a later
        // sign() could run against the key the caller thought it had replaced.
        keyId = null
        signer = null
        reset()

        val handle = privateKey as? NetHsmPrivateKeyHandle
            // Not an error: this is how JCA is told to try the next provider.
            ?: throw InvalidKeyException("not a NetHSM key")

        signer = handle.signer
            ?: throw InvalidKeyException("NetHSM key '${handle.keyId}' has no signer attached")
        keyId = handle.keyId
    }

    /**
     * Verification needs only the public key, so it has no business reaching the HSM --
     * NetHSM does not offer a verify operation either. Rejecting sends JCA to the platform
     * implementation, which is what should handle an ordinary public key.
     */
    override fun engineInitVerify(publicKey: PublicKey?) =
        throw InvalidKeyException("NetHSM keys can only be used to sign; verification is local")

    override fun engineUpdate(b: Byte) {
        md?.update(b) ?: raw.write(b.toInt())
    }

    override fun engineUpdate(b: ByteArray, off: Int, len: Int) {
        md?.update(b, off, len) ?: raw.write(b, off, len)
    }

    override fun engineSign(): ByteArray {
        val id = keyId ?: throw SignatureException("not initialised for signing")
        val hsm = signer ?: throw SignatureException("not initialised for signing")

        val message = if (md != null) {
            val hashed = md.digest()
            if (prefixDigestInfo) {
                val prefix = NetHsmAlgorithms.digestInfoPrefixFor(digest!!)
                    ?: throw SignatureException("no DigestInfo header for $digest")
                prefix + hashed
            } else {
                hashed
            }
        } else {
            raw.toByteArray()
        }
        reset()

        return try {
            // Returned verbatim: NetHSM's ECDSA mode already produces the ASN.1 DER that
            // JCA expects here, and EdDSA the raw r||s. The fixed-width conversion in
            // NetHsmAlgorithms.toJoseSignature is for JWS, which wants the other shape.
            hsm.sign(id, mode, message)
        } catch (e: Exception) {
            throw SignatureException("NetHSM failed to sign with key '$id' ($mode)", e)
        }
    }

    override fun engineVerify(sigBytes: ByteArray?): Boolean =
        throw SignatureException("this provider does not verify")

    /**
     * Accepted only when it agrees with what the mode already implies. NetHSM's PSS pairs
     * MGF1 with the message digest at the standard salt length, so parameters asking for
     * anything else must be refused rather than silently ignored.
     */
    override fun engineSetParameter(params: AlgorithmParameterSpec?) {
        when (params) {
            null -> return
            is PSSParameterSpec -> verifyPssParameters(params)
            else -> throw InvalidAlgorithmParameterException("unsupported parameters: ${params.javaClass.name}")
        }
    }

    private fun verifyPssParameters(params: PSSParameterSpec) {
        val expected = digest ?: throw InvalidAlgorithmParameterException("PSS parameters on a raw-message mode")
        val normalise = { s: String -> s.uppercase().replace("-", "") }

        if (normalise(params.digestAlgorithm) != normalise(expected)) {
            throw InvalidAlgorithmParameterException(
                "digest ${params.digestAlgorithm} does not match $expected, which this algorithm implies",
            )
        }
        val mgf1 = (params.mgfParameters as? MGF1ParameterSpec)
            ?: throw InvalidAlgorithmParameterException("only MGF1 is supported")
        if (normalise(mgf1.digestAlgorithm) != normalise(expected)) {
            throw InvalidAlgorithmParameterException(
                "NetHSM pairs MGF1 with the message digest; got ${mgf1.digestAlgorithm}",
            )
        }
        val digestLength = MessageDigest.getInstance(expected).digestLength
        if (params.saltLength != digestLength) {
            throw InvalidAlgorithmParameterException(
                "NetHSM uses a salt as long as the digest ($digestLength); got ${params.saltLength}",
            )
        }
    }

    @Deprecated("Superseded by engineSetParameter(AlgorithmParameterSpec)",
        ReplaceWith("throw UnsupportedOperationException(\"use engineSetParameter(AlgorithmParameterSpec)\")")
    )
    override fun engineSetParameter(param: String?, value: Any?) =
        throw UnsupportedOperationException("use engineSetParameter(AlgorithmParameterSpec)")

    @Deprecated("Superseded by engineGetParameters()",
        ReplaceWith("throw UnsupportedOperationException(\"use engineGetParameters()\")")
    )
    override fun engineGetParameter(param: String?): Any =
        throw UnsupportedOperationException("use engineGetParameters()")

    private fun reset() {
        md?.reset()
        raw.reset()
    }

    // One class per registered algorithm, because a SignatureSpi is never told which name
    // it was looked up under. The names are JCA's, and the RSA ones are exactly what
    // Keycloak's org.keycloak.saml.SignatureAlgorithm asks for.

    class Sha1WithRsa : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_1, "PKCS1", prefixDigestInfo = true)
    class Sha256WithRsa : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_256, "PKCS1", prefixDigestInfo = true)
    class Sha384WithRsa : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_384, "PKCS1", prefixDigestInfo = true)
    class Sha512WithRsa : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_512, "PKCS1", prefixDigestInfo = true)

    class Sha256WithRsaAndMgf1 : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_256, "PSS_SHA256", prefixDigestInfo = false)
    class Sha384WithRsaAndMgf1 : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_384, "PSS_SHA384", prefixDigestInfo = false)
    class Sha512WithRsaAndMgf1 : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_512, "PSS_SHA512", prefixDigestInfo = false)

    class Sha256WithEcdsa : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_256, "ECDSA", prefixDigestInfo = false)
    class Sha384WithEcdsa : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_384, "ECDSA", prefixDigestInfo = false)
    class Sha512WithEcdsa : NetHsmSignatureSpi(CryptoConst.TYPE_SHA_512, "ECDSA", prefixDigestInfo = false)

    class Ed25519 : NetHsmSignatureSpi(digest = null, mode = "EdDSA", prefixDigestInfo = false)
}
