package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.KeyDiscovery
import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.hsm.HsmKeyProvider
import com.nitrokey.nethsm.keycloak.hsm.HsmKeyWrapper
import com.nitrokey.nethsm.keycloak.hsm.keyTypeForAlgorithm
import org.jboss.logging.Logger
import org.keycloak.component.ComponentModel
import org.keycloak.crypto.KeyStatus
import org.keycloak.crypto.KeyUse
import org.keycloak.keys.Attributes
import java.util.stream.Stream

/**
 * Exposes every NetHSM key whose id starts with this component's configured prefix and
 * which can serve this component's algorithm.
 *
 * One component means one algorithm, mirroring Keycloak's own key providers. A realm
 * that wants both RS256 and PS256 configures two components. Two components must not
 * cover the same key, or they would publish two JWKS entries under the same `kid`.
 */
class NetHsmKeyProvider(
    private val model: ComponentModel,
    private val discovery: KeyDiscovery?,
    private val client: NetHsmClient?,
) : HsmKeyProvider() {

    private val log = Logger.getLogger(NetHsmKeyProvider::class.java)

    private val status = KeyStatus.from(
        model.get(Attributes.ACTIVE_KEY, true),
        model.get(Attributes.ENABLED_KEY, true),
    )
    private val priority = model.get(Attributes.PRIORITY_KEY, 0L)
    private val prefix = model.get(NetHsmKeyProviderFactory.KEY_PREFIX_KEY, "")
    private val algorithm = model.get(Attributes.ALGORITHM_KEY, NetHsmKeyProviderFactory.DEFAULT_ALGORITHM)

    /**
     * SIG keys sign tokens; ENC keys decrypt inbound JWE, which is the only encryption
     * direction the HSM is involved in -- encrypting to a client uses that client's
     * public key.
     */
    private val keyUse =
        if (model.get(Attributes.KEY_USE, KeyUse.SIG.getSpecName()).equals(KeyUse.ENC.getSpecName(), ignoreCase = true)) {
            KeyUse.ENC
        } else {
            KeyUse.SIG
        }

    /** Which algorithms a discovered key can serve depends on what this component is for. */
    private fun algorithmsOf(key: com.nitrokey.nethsm.keycloak.client.NetHsmKey): Set<String> = when (keyUse) {
        KeyUse.ENC -> NetHsmAlgorithms.supportedEncryptionAlgorithms(key)
        else -> NetHsmAlgorithms.supportedAlgorithms(key)
    }

    override fun getHsmKeysStream(): Stream<out HsmKeyWrapper> {
        if (discovery == null || client == null) {
            log.error(
                "NetHSM key provider is configured on this realm but the server has no NetHSM " +
                    "connection. Set spi-keys--nethsm--url (see README).",
            )
            return Stream.empty()
        }

        return discovery.keys(prefix)
            .filter { algorithm in algorithmsOf(it) }
            // Explicit, because it decides which key signs. Keycloak takes the first key
            // a provider yields, so relying on NetHSM's response order would make the
            // choice an accident of the API rather than a property of this extension.
            .sortedBy { it.id }
            .map { key ->
                NetHsmKeyWrapper(key.id, client).apply {
                    providerId = model.id
                    providerPriority = priority
                    kid = key.id
                    use = keyUse
                    type = keyTypeForAlgorithm(this@NetHsmKeyProvider.algorithm)
                    curve = NetHsmAlgorithms.curveFor(key.type)
                    this.algorithm = this@NetHsmKeyProvider.algorithm
                    this.status = this@NetHsmKeyProvider.status
                    publicKey = key.publicKey
                    // Opaque handle, not key material. Keycloak's encryption SPI only
                    // ever sees a java.security.Key, so this is how a CEK provider can
                    // tell that an unwrap belongs to the HSM. See NetHsmPrivateKeyHandle.
                    privateKey = NetHsmPrivateKeyHandle(key.id, NetHsmAlgorithms.jcaAlgorithmFor(key.type), client)
                }
            }
            .stream()
    }
}
