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
 * HSM. Serving stale metadata prevents that after a transient outage; a cold start has
 * nothing to serve, which is what [NetHsmConfig.OnUnavailable] decides.
 */
class KeyDiscovery(
    private val source: KeySource,
    private val ttl: Duration,
    private val onUnavailable: NetHsmConfig.OnUnavailable,
) {

    private val log = Logger.getLogger(KeyDiscovery::class.java)
    private val cache = ConcurrentHashMap<String, Entry>()

    private class Entry(val keys: List<NetHsmKey>, val fetchedAt: Instant)

    fun keys(prefix: String): List<NetHsmKey> {
        val cached = cache[prefix]
        if (cached != null && Duration.between(cached.fetchedAt, Instant.now()) < ttl) {
            return cached.keys
        }

        return try {
            val fresh = source.keyIds(prefix).mapNotNull { id ->
                try {
                    source.key(id)
                } catch (e: NetHsmUnavailableException) {
                    // The one failure that is not about this key. Skipping it would drop
                    // every remaining key too, and an empty result is indistinguishable
                    // from a successful discovery that found nothing -- which Keycloak
                    // answers by generating a software key. So it goes to the handler
                    // below, which serves cached keys or fails closed.
                    throw e
                } catch (e: Exception) {
                    // Anything else is this key's own problem -- NetHSM refused it, or it
                    // is malformed -- and must not sink the rest of the prefix.
                    log.warnf(e, "NetHSM key '%s' could not be read, skipping", id)
                    null
                }
            }
            cache[prefix] = Entry(fresh, Instant.now())
            log.debugf("discovered %d NetHSM key(s) for prefix '%s'", fresh.size, prefix)
            fresh
        } catch (e: Exception) {
            if (cached != null) {
                log.warnf(e, "NetHSM discovery for prefix '%s' failed, serving %d cached key(s)", prefix, cached.keys.size)
                cached.keys
            } else when (onUnavailable) {
                NetHsmConfig.OnUnavailable.FAIL -> {
                    log.errorf(
                        e,
                        "NetHSM discovery for prefix '%s' failed and nothing is cached; failing closed. " +
                            "Set spi-keys--nethsm--on-unavailable=degrade to let Keycloak carry on without the HSM.",
                        prefix,
                    )
                    throw e
                }

                NetHsmConfig.OnUnavailable.DEGRADE -> {
                    log.errorf(
                        e,
                        "NetHSM discovery for prefix '%s' failed and nothing is cached. " +
                            "on-unavailable=degrade, so Keycloak may now generate and use a SOFTWARE key " +
                            "for this realm -- tokens would then be signed outside the HSM.",
                        prefix,
                    )
                    emptyList()
                }
            }
        }
    }
}
