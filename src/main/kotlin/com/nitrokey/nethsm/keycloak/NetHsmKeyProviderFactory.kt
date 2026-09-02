package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.KeyDiscovery
import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.client.NetHsmConfig
import com.nitrokey.nethsm.keycloak.hsm.HsmKeyProviderFactory
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.component.ComponentModel
import org.keycloak.component.ComponentValidationException
import org.keycloak.crypto.Algorithm
import org.keycloak.keys.Attributes
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.RealmModel
import org.keycloak.provider.ConfigurationValidationHelper
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder

/**
 * Registers the `nethsm` key provider.
 *
 * The split is deliberate: the connection and the Operator credential come from
 * `spi-keys--nethsm--*` in `keycloak.conf` (ops-owned, secret, identical for every
 * realm), while each realm's component config only says which key ids it claims and
 * which algorithm it publishes them under.
 *
 * The HTTP client and the discovery cache live here, on the factory, so they are shared
 * by every realm and outlive individual requests.
 */
class NetHsmKeyProviderFactory : HsmKeyProviderFactory<NetHsmKeyProvider> {

    private val log = Logger.getLogger(NetHsmKeyProviderFactory::class.java)

    private var client: NetHsmClient? = null
    private var discovery: KeyDiscovery? = null
    private var configProperties: List<ProviderConfigProperty> = emptyList()

    override fun init(scope: Config.Scope) {
        configProperties = ProviderConfigurationBuilder.create()
            .property(Attributes.PRIORITY_PROPERTY)
            .property(Attributes.ENABLED_PROPERTY)
            .property(Attributes.ACTIVE_PROPERTY)
            .property(KEY_PREFIX_PROPERTY)
            .property(ALGORITHM_PROPERTY)
            .build()

        val config = NetHsmConfig.from(scope)
        if (config == null) {
            // Normal when the jar is deployed but this server has no NetHSM: stay
            // registered but inert rather than failing startup.
            log.debug("no spi-keys--nethsm--url configured; NetHSM key provider is inactive")
            return
        }

        val netHsmClient = NetHsmClient(config)
        client = netHsmClient
        discovery = KeyDiscovery(netHsmClient, config.discoveryCache, config.onUnavailable)

        log.infof(
            "NetHSM key provider ready: %d instance(s), user '%s', discovery cache %s, on-unavailable %s",
            config.urls.size, config.username, config.discoveryCache,
            config.onUnavailable.name.lowercase(),
        )

        // Startup visibility only -- deliberately not fatal, so a NetHSM that is still
        // booting or Locked does not stop Keycloak from starting. Whether an unreachable
        // NetHSM is allowed to matter is decided per request by on-unavailable.
        if (netHsmClient.ready()) {
            log.debug("NetHSM readiness probe succeeded")
        } else {
            log.warn(
                "NetHSM is not reachable or not Operational at startup. Realms using it will " +
                    "have no keys until it recovers.",
            )
        }
    }

    override fun postInit(factory: KeycloakSessionFactory) = Unit

    override fun create(session: KeycloakSession, model: ComponentModel): NetHsmKeyProvider =
        NetHsmKeyProvider(model, discovery, client)

    override fun validateConfiguration(session: KeycloakSession, realm: RealmModel, model: ComponentModel) {
        ConfigurationValidationHelper.check(model)
            .checkLong(Attributes.PRIORITY_PROPERTY, false)
            .checkBoolean(Attributes.ENABLED_PROPERTY, false)
            .checkBoolean(Attributes.ACTIVE_PROPERTY, false)
            .checkRequired(KEY_PREFIX_PROPERTY)
            .checkList(ALGORITHM_PROPERTY, false)

        val prefix = model.get(KEY_PREFIX_KEY, "")
        // NetHSM's ID schema is ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$; a prefix has to be a
        // prefix of something matching it, or discovery can never return anything.
        if (!KEY_PREFIX_PATTERN.matches(prefix)) {
            throw ComponentValidationException("Key ID prefix must match ${KEY_PREFIX_PATTERN.pattern}")
        }
    }

    override fun getId(): String = ID

    override fun getHelpText(): String = HELP_TEXT

    override fun getConfigProperties(): List<ProviderConfigProperty> = configProperties

    override fun close() {
        client?.close()
        client = null
        discovery = null
    }

    companion object {
        const val ID = "nethsm"

        private const val HELP_TEXT =
            "Uses keys stored in a Nitrokey NetHSM. Private keys never leave the HSM. " +
                "Connection and credentials come from spi-keys--nethsm--* server configuration."

        const val KEY_PREFIX_KEY = "keyPrefix"
        val KEY_PREFIX_PROPERTY = ProviderConfigProperty(
            KEY_PREFIX_KEY,
            "Key ID prefix",
            "Every NetHSM key whose id starts with this prefix is published by this realm. " +
                "Discovered via GET /keys/{prefix}*.",
            ProviderConfigProperty.STRING_TYPE,
            null,
        )

        const val DEFAULT_ALGORITHM = Algorithm.RS256
        val ALGORITHM_PROPERTY = ProviderConfigProperty(
            Attributes.ALGORITHM_KEY,
            "Algorithm",
            "Algorithm these keys are published under. A NetHSM RSA_Signature_PKCS1 key is " +
                "hash-agnostic and can serve any of RS256/384/512, so the choice is made here. " +
                "Every other mechanism implies exactly one algorithm: PSS keys from the hash " +
                "their mechanism names, EC keys from their curve, Curve25519 keys from EdDSA.",
            ProviderConfigProperty.LIST_TYPE,
            DEFAULT_ALGORITHM,
            Algorithm.RS256, Algorithm.RS384, Algorithm.RS512,
            Algorithm.PS256, Algorithm.PS384, Algorithm.PS512,
            Algorithm.ES256, Algorithm.ES384, Algorithm.ES512,
            Algorithm.EdDSA,
        )

        private val KEY_PREFIX_PATTERN = Regex("^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    }
}
