package com.nitrokey.nethsm.keycloak.client

import org.keycloak.Config
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The operator-facing surface: everything here is set by hand in keycloak.conf or an
 * environment variable, so this is where typos and paste artefacts land.
 */
class NetHsmConfigTest {

    /**
     * Minimal Config.Scope over a map, matching how Keycloak splits comma-separated
     * values. Some of the interface's accessors are deprecated upstream but still
     * abstract, so implementing them is not optional.
     */
    @Suppress("OVERRIDE_DEPRECATION")
    private class MapScope(private val values: Map<String, String>) : Config.Scope {
        override fun get(key: String): String? = values[key]
        override fun get(key: String, default: String?): String? = values[key] ?: default
        override fun getArray(key: String): Array<String>? =
            values[key]?.split(",")?.map { it.trim() }?.toTypedArray()
        override fun getInt(key: String, default: Int?): Int? = values[key]?.toInt() ?: default
        override fun getLong(key: String, default: Long?): Long? = values[key]?.toLong() ?: default
        override fun getBoolean(key: String, default: Boolean?): Boolean? =
            values[key]?.toBoolean() ?: default
        override fun scope(vararg s: String): Config.Scope = this
        override fun getPropertyNames(): Set<String> = values.keys
        override fun root(): Config.Scope = this
    }

    private fun scope(vararg pairs: Pair<String, String>) = MapScope(mapOf(*pairs))

    private val minimal = arrayOf(
        "url" to "https://hsm:8443/api/v1",
        "username" to "operator",
        "passphrase" to "0123456789",
    )

    @Test
    fun `no url means the extension stays inert rather than failing startup`() {
        assertNull(NetHsmConfig.from(scope("username" to "u", "passphrase" to "p")))
    }

    @Test
    fun `credentials are required once a url is given`() {
        assertFailsWith<IllegalStateException> {
            NetHsmConfig.from(scope("url" to "https://hsm:8443/api/v1"))
        }
        assertFailsWith<IllegalStateException> {
            NetHsmConfig.from(scope("url" to "https://hsm:8443/api/v1", "username" to "u"))
        }
    }

    @Test
    fun `defaults match what the README documents`() {
        val config = NetHsmConfig.from(scope(*minimal))!!
        assertEquals(Duration.ofSeconds(10), config.timeout)
        assertEquals(Duration.ofSeconds(3), config.connectTimeout)
        assertEquals(2, config.retries)
        assertEquals(Duration.ofMillis(200), config.retryDelay)
        assertEquals(20, config.maxConnections)
        assertEquals(Duration.ofSeconds(300), config.discoveryCache)
        assertEquals(Duration.ofHours(24), config.discoveryMaxStale)
        assertEquals(NetHsmConfig.OnUnavailable.FAIL, config.onUnavailable, "must default to failing closed")
        assertEquals(false, config.tlsInsecure)
        assertTrue(config.tlsFingerprints.isEmpty())
    }

    @Test
    fun `several urls are accepted, which is what makes failover possible`() {
        val config = NetHsmConfig.from(
            scope("url" to "https://a:8443/api/v1, https://b:8443/api/v1", *minimal.drop(1).toTypedArray()),
        )!!
        assertEquals(listOf("https://a:8443/api/v1", "https://b:8443/api/v1"), config.urls)
    }

    /** `openssl x509 -fingerprint` prints upper case with colons; operators paste that verbatim. */
    @Test
    fun `fingerprints are normalised from the form openssl prints`() {
        val config = NetHsmConfig.from(
            scope(*minimal, "tls-fingerprints" to "AA:BB:CC:DD, ee:ff:00:11"),
        )!!
        assertEquals(setOf("aabbccdd", "eeff0011"), config.tlsFingerprints)
    }

    @Test
    fun `pinning and disabling verification together is refused as contradictory`() {
        assertFailsWith<IllegalArgumentException> {
            NetHsmConfig.from(scope(*minimal, "tls-insecure" to "true", "tls-fingerprints" to "aabb"))
        }
    }

    @Test
    fun `on-unavailable accepts either case and rejects anything else`() {
        assertEquals(
            NetHsmConfig.OnUnavailable.DEGRADE,
            NetHsmConfig.from(scope(*minimal, "on-unavailable" to "degrade"))!!.onUnavailable,
        )
        assertEquals(
            NetHsmConfig.OnUnavailable.DEGRADE,
            NetHsmConfig.from(scope(*minimal, "on-unavailable" to "DEGRADE"))!!.onUnavailable,
        )
        assertFailsWith<IllegalStateException> {
            NetHsmConfig.from(scope(*minimal, "on-unavailable" to "maybe"))
        }
    }

    /**
     * The connect timeout is what an outage makes every request thread wait out, so it is
     * bounded separately from the overall timeout and has to be settable on its own.
     */
    @Test
    fun `connect timeout is configurable independently of the overall timeout`() {
        val config = NetHsmConfig.from(
            scope(*minimal, "timeout-seconds" to "30", "connect-timeout-seconds" to "1"),
        )!!
        assertEquals(Duration.ofSeconds(30), config.timeout)
        assertEquals(Duration.ofSeconds(1), config.connectTimeout)
    }

    @Test
    fun `the max-stale bound is configurable`() {
        val config = NetHsmConfig.from(scope(*minimal, "discovery-max-stale-seconds" to "60"))!!
        assertEquals(Duration.ofSeconds(60), config.discoveryMaxStale)
    }

    @Test
    fun `blank url entries are dropped rather than becoming an endpoint`() {
        val config = NetHsmConfig.from(
            scope("url" to "https://a:8443/api/v1, ,", *minimal.drop(1).toTypedArray()),
        )!!
        assertEquals(listOf("https://a:8443/api/v1"), config.urls)
    }
}
