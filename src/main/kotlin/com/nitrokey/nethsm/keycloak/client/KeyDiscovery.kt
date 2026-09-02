package com.nitrokey.nethsm.keycloak.client

import org.jboss.logging.Logger
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * Caches the result of prefix discovery, shared across realms by the provider factory.
 *
 * Entries are only ever replaced by a successful refresh, never evicted on failure, so a
 * NetHSM that is briefly unreachable or `Locked` does not take the realm's keys with it.
 *
 * That matters more than it looks. If a provider yields no keys, `DefaultKeyManager`
 * logs "No keys found for realm={0} and algorithm={1} for use={2}. Generating keys." and
 * generates a *software* key, and Keycloak carries on issuing tokens signed outside the
 * HSM. Serving stale metadata is what keeps that from happening after a transient
 * outage; see the README for the cold-start case, which this cannot cover.
 */
class KeyDiscovery(private val client: NetHsmClient, private val ttl: Duration) {

    private val log = Logger.getLogger(KeyDiscovery::class.java)
    private val cache = ConcurrentHashMap<String, Entry>()

    private class Entry(val keys: List<NetHsmKey>, val fetchedAt: Instant)

    fun keys(prefix: String): List<NetHsmKey> {
        val cached = cache[prefix]
        if (cached != null && Duration.between(cached.fetchedAt, Instant.now()) < ttl) {
            return cached.keys
        }

        return try {
            val fresh = client.keyIds(prefix).mapNotNull { id ->
                runCatching { client.key(id) }
                    .onFailure { log.warnf(it, "NetHSM key '%s' could not be read, skipping", id) }
                    .getOrNull()
            }
            cache[prefix] = Entry(fresh, Instant.now())
            log.debugf("discovered %d NetHSM key(s) for prefix '%s'", fresh.size, prefix)
            fresh
        } catch (e: Exception) {
            if (cached != null) {
                log.warnf(e, "NetHSM discovery for prefix '%s' failed, serving %d cached key(s)", prefix, cached.keys.size)
                cached.keys
            } else {
                log.errorf(
                    e,
                    "NetHSM discovery for prefix '%s' failed and nothing is cached. " +
                        "Keycloak may now generate a software key for this realm.",
                    prefix,
                )
                emptyList()
            }
        }
    }
}
