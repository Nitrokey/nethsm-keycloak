package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import org.keycloak.crypto.JavaAlgorithm
import org.keycloak.crypto.SignatureException
import org.keycloak.crypto.SignatureSignerContext
import java.security.MessageDigest

/**
 * Hashes locally, then has NetHSM apply the padding and the private key.
 *
 * The private key never leaves the HSM, and the only thing crossing the wire is a
 * digest.
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
        val digest = MessageDigest.getInstance(getHashAlgorithm()).digest(data)

        // PKCS1 mode signs the value verbatim, so EMSA-PKCS1-v1_5 requires the
        // DigestInfo header. PSS_* derives it from the mode and wants the bare digest.
        val message = NetHsmAlgorithms.digestInfoPrefix(algorithm)?.plus(digest) ?: digest

        return try {
            client.sign(key.keyId, NetHsmAlgorithms.signMode(algorithm), message)
        } catch (e: Exception) {
            throw SignatureException("NetHSM failed to sign with key '${key.keyId}' ($algorithm)", e)
        }
    }
}
