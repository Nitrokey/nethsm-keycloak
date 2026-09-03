package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.KeyDiscovery
import com.nitrokey.nethsm.keycloak.client.KeySource
import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.client.NetHsmConfig
import com.nitrokey.nethsm.keycloak.client.NetHsmConnection
import com.nitrokey.nethsm.keycloak.client.NetHsmKey
import org.keycloak.common.util.MultivaluedHashMap
import org.keycloak.component.ComponentModel
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.KeyStatus
import org.keycloak.crypto.KeyType
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.KeyWrapper
import org.keycloak.jose.jwe.JWEConstants
import java.security.KeyPairGenerator
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * What a realm ends up publishing, given a component's configuration.
 *
 * Previously reachable only through the container stack, which made a three-minute
 * integration run the cheapest way to check a filtering or status change.
 */
class NetHsmKeyProviderTest {

    private val publicKey = KeyPairGenerator.getInstance("RSA")
        .apply { initialize(2048) }
        .generateKeyPair().public

    private fun key(id: String, vararg mechanisms: String) =
        NetHsmKey(id, "RSA", mechanisms.toSet(), publicKey)

    private val signing = "RSA_Signature_PKCS1"
    private val decrypting = "RSA_Decryption_OAEP_SHA256"

    private fun connection(vararg keys: NetHsmKey): NetHsmConnection {
        val source = object : KeySource {
            override fun keyIds(prefix: String) = keys.filter { it.id.startsWith(prefix) }.map { it.id }
            override fun key(id: String) = keys.firstOrNull { it.id == id }
        }
        // The client is never dereferenced by these tests; only its identity travels into
        // the wrapper, so a config pointing nowhere is fine.
        val config = NetHsmConfig(
            urls = listOf("https://localhost:1/api/v1"),
            username = "u",
            passphrase = "0123456789",
            tlsFingerprints = emptySet(),
            tlsInsecure = true,
            timeout = Duration.ofSeconds(1),
            retries = 0,
            retryDelay = Duration.ZERO,
            maxConnections = 1,
            onUnavailable = NetHsmConfig.OnUnavailable.FAIL,
            discoveryCache = Duration.ofMinutes(5),
        )
        return NetHsmConnection(
            NetHsmClient(config),
            KeyDiscovery(source, Duration.ofMinutes(5), NetHsmConfig.OnUnavailable.FAIL),
        )
    }

    private fun model(vararg config: Pair<String, String>) = ComponentModel().apply {
        id = "component-1"
        this.config = MultivaluedHashMap<String, String>().apply {
            config.forEach { (k, v) -> putSingle(k, v) }
        }
    }

    private fun keysOf(model: ComponentModel, connection: NetHsmConnection?): List<KeyWrapper> =
        NetHsmKeyProvider(model, connection).getKeysStream().toList()

    // --- selection -------------------------------------------------------------------

    @Test
    fun `publishes only keys under the prefix that can serve the algorithm`() {
        val keys = keysOf(
            model("keyPrefix" to "kc-", "algorithm" to Algorithm.RS256),
            connection(key("kc-signs", signing), key("kc-decrypts", decrypting), key("other", signing)),
        )
        assertEquals(listOf("kc-signs"), keys.map { it.kid })
    }

    @Test
    fun `an encryption component publishes decrypt keys and ignores signing keys`() {
        val keys = keysOf(
            model("keyPrefix" to "kc-", "algorithm" to JWEConstants.RSA_OAEP_256, "keyUse" to "enc"),
            connection(key("kc-signs", signing), key("kc-decrypts", decrypting)),
        )
        assertEquals(listOf("kc-decrypts"), keys.map { it.kid })
        assertEquals(KeyUse.ENC, keys.single().use)
    }

    @Test
    fun `keys are published in ID order, since the first one signs`() {
        val keys = keysOf(
            model("keyPrefix" to "kc-", "algorithm" to Algorithm.RS256),
            connection(key("kc-c", signing), key("kc-a", signing), key("kc-b", signing)),
        )
        assertEquals(listOf("kc-a", "kc-b", "kc-c"), keys.map { it.kid })
    }

    @Test
    fun `a prefix matching nothing publishes nothing rather than failing`() {
        val keys = keysOf(
            model("keyPrefix" to "absent", "algorithm" to Algorithm.RS256),
            connection(key("kc-signs", signing)),
        )
        assertTrue(keys.isEmpty())
    }

    // --- what ends up on the wrapper ---------------------------------------------------

    @Test
    fun `the wrapper carries the identity and metadata Keycloak publishes`() {
        val wrapper = keysOf(
            model("keyPrefix" to "kc-", "algorithm" to Algorithm.RS256, "priority" to "250"),
            connection(key("kc-signs", signing)),
        ).single()

        assertEquals("kc-signs", wrapper.kid, "kid is the NetHSM key ID, so it is stable")
        assertEquals(Algorithm.RS256, wrapper.algorithm)
        assertEquals(KeyType.RSA, wrapper.type)
        assertEquals(KeyUse.SIG, wrapper.use)
        assertEquals(250L, wrapper.providerPriority)
        assertEquals("component-1", wrapper.providerId)
        assertEquals(publicKey, wrapper.publicKey)
    }

    /** The private key must be a handle, never material: that is the point of the HSM. */
    @Test
    fun `the private key is an opaque handle carrying no material`() {
        val wrapper = keysOf(
            model("keyPrefix" to "kc-", "algorithm" to Algorithm.RS256),
            connection(key("kc-signs", signing)),
        ).single()

        val handle = assertIs<NetHsmPrivateKeyHandle>(wrapper.privateKey)
        assertEquals("kc-signs", handle.keyId)
        assertEquals(null, handle.encoded)
        assertEquals(null, handle.format)
    }

    // --- status ------------------------------------------------------------------------

    @Test
    fun `active and enabled decide the status rotation relies on`() {
        fun statusFor(active: String, enabled: String) = keysOf(
            model("keyPrefix" to "kc-", "algorithm" to Algorithm.RS256, "active" to active, "enabled" to enabled),
            connection(key("kc-signs", signing)),
        ).single().status

        assertEquals(KeyStatus.ACTIVE, statusFor("true", "true"))
        assertEquals(KeyStatus.PASSIVE, statusFor("false", "true"), "passive keys still verify during rotation")
        assertEquals(KeyStatus.DISABLED, statusFor("true", "false"))
    }

    // --- no connection -------------------------------------------------------------------

    @Test
    fun `an unconfigured server yields no keys rather than throwing`() {
        val keys = keysOf(model("keyPrefix" to "kc-", "algorithm" to Algorithm.RS256), connection = null)
        assertTrue(keys.isEmpty())
    }
}
