package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.hsm.HsmKeyWrapper
import org.keycloak.crypto.ServerAsymmetricSignatureVerifierContext
import org.keycloak.crypto.SignatureSignerContext
import org.keycloak.crypto.SignatureVerifierContext

/**
 * A realm key backed by a NetHSM key.
 *
 * [keyId] is the NetHSM key id and also the `kid` Keycloak publishes: it is stable
 * across restarts and across cluster nodes, which a generated ID stored in component
 * config would not be under auto-discovery.
 */
class NetHsmKeyWrapper( 
    val keyId: String,
    private val client: NetHsmClient,
) : HsmKeyWrapper() {

    override fun createSignatureSignerContext(): SignatureSignerContext =
        NetHsmSignatureSignerContext(this, client)

    /**
     * Verification runs locally against the public key -- no HSM round trip, which is
     * also the only option: NetHSM does not offer a verify operation.
     */
    override fun createSignatureVerifierContext(): SignatureVerifierContext =
        ServerAsymmetricSignatureVerifierContext(this)
}
