package com.nitrokey.nethsm.keycloak.client

import java.io.Closeable

/**
 * The connected NetHSM: a client and the discovery cache built on it.
 *
 * They are one thing, not two. The cache is constructed *from* the client, the factory
 * creates and discards them together, and a provider holding one without the other could
 * do nothing useful — so a single nullable reference says "configured or not" where two
 * would admit two states that never occur.
 */
class NetHsmConnection(
    val client: NetHsmClient,
    val discovery: KeyDiscovery,
) : Closeable {

    override fun close() = client.close()

    companion object {
        fun open(config: NetHsmConfig): NetHsmConnection {
            val client = NetHsmClient(config)
            return NetHsmConnection(
                client,
                KeyDiscovery(client, config.discoveryCache, config.onUnavailable, config.discoveryMaxStale),
            )
        }
    }
}
