package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import org.keycloak.crypto.JavaAlgorithm
import org.keycloak.crypto.SignatureException
import org.keycloak.crypto.SignatureSignerContext
import java.security.MessageDigest

/**
 * Hashes locally where the algorithm calls for it, then has NetHSM apply the padding and
 * the private key.
 *
 * The private key never leaves the HSM, and for everything except Ed25519 the only thing
 * crossing the wire is a digest.
 */
class NetHsmSignatureSignerContext(
    private val key: NetHsmKeyWrapper,
    private val client: NetHsmClient,
) : SignatureSignerContext {

    override fun getKid(): String = key.kid

    override fun getAlgorithm(): String = key.algorithm

    override fun getHashAlgorithm(): String = JavaAlgorithm.getJavaAlgorithmForHash(key.algorithm)

    override fun sign(data: ByteArray): ByteArray {
        val algorithm = key.algorithm

        val message = if (NetHsmAlgorithms.signsRawMessage(algorithm)) {
            // Ed25519 hashes the message internally and derives its nonce from that
            // hash, so it has to see the message itself.
            data
        } else {
            val digest = MessageDigest.getInstance(getHashAlgorithm()).digest(data)
            // PKCS1 mode signs the value verbatim, so EMSA-PKCS1-v1_5 needs the
            // DigestInfo header. PSS_* and ECDSA want the bare digest.
            NetHsmAlgorithms.digestInfoPrefix(algorithm)?.plus(digest) ?: digest
        }

        return try {
            val signature = client.sign(key.keyId, NetHsmAlgorithms.signMode(algorithm), message)
            NetHsmAlgorithms.toJoseSignature(algorithm, signature)
        } catch (e: Exception) {
            throw SignatureException("NetHSM failed to sign with key '${key.keyId}' ($algorithm)", e)
        }
    }
}
