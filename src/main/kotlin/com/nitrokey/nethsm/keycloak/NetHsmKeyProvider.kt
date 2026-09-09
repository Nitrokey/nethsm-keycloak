package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.NetHsmConnection
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
 * Exposes every NetHSM key whose ID starts with this component's configured prefix and
 * which can serve this component's algorithm.
 *
 * One component means one algorithm, mirroring Keycloak's own key providers. A realm
 * that wants both RS256 and PS256 configures two components. Two components must not
 * cover the same key, or they would publish two JWKS entries under the same `kid`.
 */
class NetHsmKeyProvider(
    model: ComponentModel,
    private val connection: NetHsmConnection?,
) : HsmKeyProvider() {

    // Everything the provider needs is derived once, here: a new instance is built per
    // request, and re-reading the model mid-stream would suggest it can change under us.
    private val providerId = model.id
    private val status = KeyStatus.from(
        model.get(Attributes.ACTIVE_KEY, true),
        model.get(Attributes.ENABLED_KEY, true),
    )
    private val priority = model.get(Attributes.PRIORITY_KEY, 0L)
    private val prefix = model.get(NetHsmKeyProviderFactory.KEY_PREFIX_KEY, "")
    private val algorithm = model.get(Attributes.ALGORITHM_KEY, NetHsmKeyProviderFactory.DEFAULT_ALGORITHM)
    private val keyUse = NetHsmKeyProviderFactory.keyUseOf(model)

    /** Fixed for the provider's lifetime, so it is resolved once rather than per key. */
    private val keyType = keyTypeForAlgorithm(algorithm)

    override fun getHsmKeysStream(): Stream<out HsmKeyWrapper> {
        val connection = connection ?: run {
            log.error(
                "NetHSM key provider is configured on this realm but the server has no NetHSM " +
                    "connection. Set spi-keys--nethsm--url (see README).",
            )
            return Stream.empty()
        }

        // KeyDiscovery returns keys ordered by ID, which is what decides who signs.
        return connection.discovery.keys(prefix)
            .filter { algorithm in NetHsmAlgorithms.algorithmsFor(it, keyUse) }
            .map { key ->
                NetHsmKeyWrapper(key.id, connection.client).also { wrapper ->
                    wrapper.providerId = providerId
                    wrapper.providerPriority = priority
                    wrapper.kid = key.id
                    wrapper.use = keyUse
                    wrapper.type = keyType
                    wrapper.curve = NetHsmAlgorithms.curveFor(key.type)
                    wrapper.algorithm = algorithm
                    wrapper.status = status
                    wrapper.publicKey = key.publicKey
                    // Opaque handle, not key material. Keycloak's encryption SPI only
                    // ever sees a java.security.Key, and SAML hands the bare PrivateKey
                    // to XML-DSig, so this is how the JCA provider can tell that an
                    // unwrap or a signature belongs to the HSM. See NetHsmPrivateKeyHandle.
                    wrapper.privateKey = NetHsmPrivateKeyHandle(
                        key.id,
                        NetHsmAlgorithms.jcaAlgorithmFor(key.type),
                        decryptor = connection.client,
                        signer = connection.client,
                    )
                }
            }
            .stream()
    }

    private companion object {
        private val log = Logger.getLogger(NetHsmKeyProvider::class.java)
    }
}
