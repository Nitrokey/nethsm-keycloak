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
