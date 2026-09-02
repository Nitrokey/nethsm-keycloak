package com.nitrokey.nethsm.keycloak.client

/**
 * The two NetHSM reads discovery needs, separated from [NetHsmClient] so the
 * fail-closed/degrade branches in [KeyDiscovery] can be tested without a NetHSM.
 */
interface KeySource {

    /** Ids of every key whose id starts with [prefix]. */
    fun keyIds(prefix: String): List<String>

    /** Metadata for one key, or null if this extension cannot represent its type. */
    fun key(id: String): NetHsmKey?
}
