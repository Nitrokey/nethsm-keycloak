package com.nitrokey.nethsm.keycloak.client

/**
 * The single NetHSM operation a JCA signature needs.
 *
 * Narrow for the same reason as [CekDecryptor]: a key handle should be able to do exactly
 * the operations it is for, and nothing that holds one should gain the ability to discover
 * keys or read configuration.
 */
fun interface MessageSigner {

    /**
     * Signs [message] with the NetHSM key [keyId].
     *
     * @param mode a NetHSM `SignMode`, e.g. `PKCS1` or `PSS_SHA256`. What [message] has to
     *   be depends on it: a DigestInfo-prefixed digest for `PKCS1`, a bare digest for
     *   `PSS_*` and `ECDSA`, the raw message for `EdDSA`.
     */
    fun sign(keyId: String, mode: String, message: ByteArray): ByteArray
}
