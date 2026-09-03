package com.nitrokey.nethsm.keycloak.client

/**
 * The single NetHSM operation a JWE unwrap needs.
 *
 * Narrower than handing [NetHsmClient] itself to a key handle: the handle should be able
 * to do exactly one thing, and nothing that holds it gains the ability to sign, discover
 * keys, or read configuration.
 */
fun interface CekDecryptor {

    /**
     * Decrypts an encrypted content encryption key.
     *
     * @param mode a NetHSM `DecryptMode`, e.g. `OAEP_SHA256`.
     */
    fun decryptCek(keyId: String, mode: String, ciphertext: ByteArray): ByteArray
}
