package com.nitrokey.nethsm.keycloak.jca

import com.nitrokey.nethsm.keycloak.NetHsmPrivateKeyHandle
import org.jboss.logging.Logger
import java.security.Provider
import java.security.Security

/**
 * A JCA provider offering exactly one thing: RSA-OAEP decryption with a key held in
 * NetHSM.
 *
 * Registered *last*, so the platform implementation is always tried first. JCA defers
 * provider selection for `Cipher` until `init`, and moves on when a provider rejects the
 * key, so ordinary RSA keys never reach this code and behaviour for them is unchanged.
 * `SupportedKeyClasses` lets JCA skip this provider without instantiating anything.
 */
class NetHsmSecurityProvider : Provider(NAME, "1.0", "NetHSM-backed RSA-OAEP decryption") {

    init {
        put("Cipher.RSA", NetHsmCipherSpi::class.java.name)
        put("Cipher.RSA SupportedModes", "ECB")
        put(
            "Cipher.RSA SupportedPaddings",
            listOf(
                "OAEPWITHSHA-1ANDMGF1PADDING",
                "OAEPWITHSHA-256ANDMGF1PADDING",
                "OAEPWITHSHA-384ANDMGF1PADDING",
                "OAEPWITHSHA-512ANDMGF1PADDING",
            ).joinToString("|"),
        )
        put("Cipher.RSA SupportedKeyClasses", NetHsmPrivateKeyHandle::class.java.name)

        // Signing, for the callers that never see a Keycloak KeyWrapper and go straight
        // to java.security.Signature. SAML is the one that matters: XML-DSig signs with
        // the bare PrivateKey, so without these an assertion cannot be signed by the HSM.
        // The RSA entries are exactly the names org.keycloak.saml.SignatureAlgorithm uses,
        // minus SHA1withDSA, which NetHSM has no key type for.
        signature("SHA1withRSA", NetHsmSignatureSpi.Sha1WithRsa::class.java)
        signature("SHA256withRSA", NetHsmSignatureSpi.Sha256WithRsa::class.java)
        signature("SHA384withRSA", NetHsmSignatureSpi.Sha384WithRsa::class.java)
        signature("SHA512withRSA", NetHsmSignatureSpi.Sha512WithRsa::class.java)
        signature("SHA256withRSAandMGF1", NetHsmSignatureSpi.Sha256WithRsaAndMgf1::class.java)
        signature("SHA384withRSAandMGF1", NetHsmSignatureSpi.Sha384WithRsaAndMgf1::class.java)
        signature("SHA512withRSAandMGF1", NetHsmSignatureSpi.Sha512WithRsaAndMgf1::class.java)
        signature("SHA256withECDSA", NetHsmSignatureSpi.Sha256WithEcdsa::class.java)
        signature("SHA384withECDSA", NetHsmSignatureSpi.Sha384WithEcdsa::class.java)
        signature("SHA512withECDSA", NetHsmSignatureSpi.Sha512WithEcdsa::class.java)
        signature("Ed25519", NetHsmSignatureSpi.Ed25519::class.java)
    }

    /**
     * `SupportedKeyClasses` is what lets JCA skip this provider for an ordinary key
     * without instantiating anything, so it is set for every algorithm rather than left
     * to the InvalidKeyException in the SPI.
     */
    private fun signature(name: String, spi: Class<*>) {
        put("Signature.$name", spi.name)
        put("Signature.$name SupportedKeyClasses", NetHsmPrivateKeyHandle::class.java.name)
    }

    companion object {
        const val NAME = "NetHSM"

        private val log = Logger.getLogger(NetHsmSecurityProvider::class.java)

        /**
         * Installs the provider once per JVM, at the end of the preference order.
         *
         * Idempotent: Keycloak may initialise the key provider factory more than once,
         * and adding a duplicate would shift provider positions for everything else.
         */
        fun install() {
            if (Security.getProvider(NAME) != null) return
            // addProvider appends, which is what keeps the platform provider first.
            val position = Security.addProvider(NetHsmSecurityProvider())
            log.infof("registered the NetHSM JCA provider at position %d", position)
        }
    }
}
