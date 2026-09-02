package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.KeyDiscovery
import com.nitrokey.nethsm.keycloak.client.KeySource
import com.nitrokey.nethsm.keycloak.client.NetHsmConfig
import com.nitrokey.nethsm.keycloak.client.NetHsmKey
import com.nitrokey.nethsm.keycloak.client.NetHsmUnavailableException
import java.security.KeyPairGenerator
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The behaviour these tests pin down is a security property, not just robustness.
 *
 * A provider that contributes no keys is not neutral: `DefaultKeyManager` reacts to a
 * realm with no active key by asking the generated key provider factories for a
 * fallback, and Keycloak then signs tokens with a software key. So "discovery failed"
 * must never quietly become "no keys" unless the operator asked for that.
 */
class KeyDiscoveryTest {

    private val publicKey = KeyPairGenerator.getInstance("RSA")
        .apply { initialize(2048) }
        .generateKeyPair().public

    private class FakeSource(var keys: List<NetHsmKey>) : KeySource {
        var failing = false

        /**
         * Separate from [failing] on purpose. An outage that begins *after* the list call
         * is a different path, and while these were one flag it could not be reached --
         * which is how discovery came to fail open there.
         */
        var failingPerKey = false
        var calls = 0

        override fun keyIds(prefix: String): List<String> {
            calls++
            if (failing) throw NetHsmUnavailableException("NetHSM is down")
            return keys.filter { it.id.startsWith(prefix) }.map { it.id }
        }

        override fun key(id: String): NetHsmKey? {
            if (failing || failingPerKey) throw NetHsmUnavailableException("NetHSM is down")
            return keys.firstOrNull { it.id == id }
        }
    }

    private fun rsaKey(id: String) = NetHsmKey(id, "RSA", setOf("RSA_Signature_PKCS1"), publicKey)

    private fun discovery(
        source: KeySource,
        onUnavailable: NetHsmConfig.OnUnavailable = NetHsmConfig.OnUnavailable.FAIL,
        ttl: Duration = Duration.ofMinutes(5),
    ) = KeyDiscovery(source, ttl, onUnavailable)

    @Test
    fun `discovers keys matching the prefix and nothing else`() {
        val source = FakeSource(listOf(rsaKey("kc-a"), rsaKey("kc-b"), rsaKey("other")))
        assertEquals(listOf("kc-a", "kc-b"), discovery(source).keys("kc-").map { it.id })
    }

    @Test
    fun `repeated lookups inside the ttl do not hit NetHSM again`() {
        val source = FakeSource(listOf(rsaKey("kc-a")))
        val discovery = discovery(source)
        repeat(5) { discovery.keys("kc-") }
        assertEquals(1, source.calls)
    }

    @Test
    fun `a lookup after the ttl refreshes`() {
        val source = FakeSource(listOf(rsaKey("kc-a")))
        val discovery = discovery(source, ttl = Duration.ZERO)
        discovery.keys("kc-")
        discovery.keys("kc-")
        assertEquals(2, source.calls)
    }

    @Test
    fun `a failure with a warm cache serves the cached keys, so no software key is generated`() {
        val source = FakeSource(listOf(rsaKey("kc-a")))
        val discovery = discovery(source, ttl = Duration.ZERO)
        assertEquals(1, discovery.keys("kc-").size)

        source.failing = true
        assertEquals(listOf("kc-a"), discovery.keys("kc-").map { it.id }, "must fall back to cache")
    }

    @Test
    fun `a failure with a cold cache fails closed by default`() {
        val source = FakeSource(emptyList()).apply { failing = true }
        assertFailsWith<NetHsmUnavailableException> {
            discovery(source).keys("kc-")
        }
    }

    @Test
    fun `a failure with a cold cache yields no keys only when degrade was chosen`() {
        val source = FakeSource(emptyList()).apply { failing = true }
        val keys = discovery(source, onUnavailable = NetHsmConfig.OnUnavailable.DEGRADE).keys("kc-")
        assertTrue(keys.isEmpty())
    }

    @Test
    fun `one unreadable key does not sink discovery for the rest`() {
        val source = object : KeySource {
            override fun keyIds(prefix: String) = listOf("good", "broken")
            override fun key(id: String): NetHsmKey? =
                if (id == "broken") throw IllegalStateException("unparseable") else rsaKey(id)
        }
        assertEquals(listOf("good"), discovery(source).keys("").map { it.id })
    }

    /**
     * The list call succeeding does not mean the per-key reads will. If NetHSM goes away
     * in between, every key is dropped and the result is an empty list -- which is not
     * "this prefix matches nothing", it is a failed discovery, and must be treated as one.
     * Otherwise the fail-closed policy is bypassed entirely and Keycloak generates a
     * software key while `on-unavailable=fail` is set.
     */
    @Test
    fun `an outage after the list call fails closed rather than yielding no keys`() {
        val source = FakeSource(listOf(rsaKey("kc-a"), rsaKey("kc-b"))).apply { failingPerKey = true }
        assertFailsWith<NetHsmUnavailableException> { discovery(source).keys("kc-") }
    }

    @Test
    fun `an outage after the list call does not get cached as an empty result`() {
        val source = FakeSource(listOf(rsaKey("kc-a"))).apply { failingPerKey = true }
        val discovery = discovery(source, onUnavailable = NetHsmConfig.OnUnavailable.DEGRADE)
        assertTrue(discovery.keys("kc-").isEmpty(), "degrade yields nothing, as configured")

        // If the empty result had been cached, recovery would stay invisible for the ttl.
        source.failingPerKey = false
        assertEquals(listOf("kc-a"), discovery.keys("kc-").map { it.id }, "must retry, not serve a cached empty")
    }

    @Test
    fun `an outage after the list call still serves a warm cache`() {
        val source = FakeSource(listOf(rsaKey("kc-a")))
        val discovery = discovery(source, ttl = Duration.ZERO)
        assertEquals(1, discovery.keys("kc-").size)

        source.failingPerKey = true
        assertEquals(listOf("kc-a"), discovery.keys("kc-").map { it.id })
    }
}
