package com.nitrokey.nethsm.keycloak.client

import org.jboss.logging.Logger
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap

/**
 * Caches the result of prefix discovery, shared across realms by the provider factory.
 *
 * Entries are only ever replaced by a successful refresh, never evicted on failure, so a
 * NetHSM that is briefly unreachable or `Locked` does not take the realm's keys with it.
 * [maxStale] caps that, so "briefly" cannot quietly become "for a week".
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
    private val maxStale: Duration = Duration.ofHours(24),
) {

    private val log = Logger.getLogger(KeyDiscovery::class.java)
    private val cache = ConcurrentHashMap<String, Entry>()
    private val refreshLocks = ConcurrentHashMap<String, Any>()

    private class Entry(val keys: List<NetHsmKey>, val fetchedAtNanos: Long)

    /**
     * Keys whose ID starts with [prefix], **ordered by ID**.
     *
     * The order is part of the contract, not incidental: Keycloak signs with the first
     * key a provider yields, so this is what decides which key signs. Establishing it
     * here makes it an invariant of the cached entry, computed once per refresh, rather
     * than something every caller has to remember to reapply.
     */
    fun keys(prefix: String): List<NetHsmKey> {
        cachedWithinTtl(prefix)?.let { return it }

        // One refresh at a time per prefix. Without this, every request arriving after
        // the ttl expires starts its own, so a single expiry becomes a burst of
        // (1 + keys) NetHSM calls per in-flight request.
        return synchronized(refreshLocks.computeIfAbsent(prefix) { Any() }) {
            // Another thread may have finished a refresh while this one waited.
            cachedWithinTtl(prefix) ?: refresh(prefix)
        }
    }

    private fun cachedWithinTtl(prefix: String): List<NetHsmKey>? {
        val cached = cache[prefix] ?: return null
        // nanoTime, not Instant: this runs on every key lookup, and a monotonic long
        // comparison neither allocates nor trips over a wall-clock jump.
        return if (System.nanoTime() - cached.fetchedAtNanos < ttl.toNanos()) cached.keys else null
    }

    private fun refresh(prefix: String): List<NetHsmKey> {
        val cached = cache[prefix]

        return try {
            val fresh = source.keyIds(prefix).sorted().mapNotNull { id ->
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
            cache[prefix] = Entry(fresh, System.nanoTime())
            log.debugf("discovered %d NetHSM key(s) for prefix '%s'", fresh.size, prefix)
            fresh
        } catch (e: Exception) {
            val servable = cached?.takeIf { System.nanoTime() - it.fetchedAtNanos <= maxStale.toNanos() }
            if (cached != null && servable == null) {
                log.warnf(
                    "cached keys for prefix '%s' are older than the %s limit, so they are being " +
                        "discarded rather than published indefinitely; a key rotated or deleted in " +
                        "NetHSM would otherwise stay in this realm's JWKS.",
                    prefix, maxStale,
                )
            }

            if (servable != null) {
                log.warnf(e, "NetHSM discovery for prefix '%s' failed, serving %d cached key(s)", prefix, servable.keys.size)
                servable.keys
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
