package com.nitrokey.nethsm.keycloak

import com.nitrokey.nethsm.keycloak.client.KeyDiscovery
import com.nitrokey.nethsm.keycloak.client.NetHsmClient
import com.nitrokey.nethsm.keycloak.client.NetHsmConfig
import com.nitrokey.nethsm.keycloak.hsm.HsmKeyProviderFactory
import com.nitrokey.nethsm.keycloak.jca.NetHsmSecurityProvider
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.component.ComponentModel
import org.keycloak.component.ComponentValidationException
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.KeyUse
import org.keycloak.jose.jwe.JWEConstants
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
            .property(KEY_USE_PROPERTY)
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

        // Keycloak decrypts inbound JWE through plain JCA, not through its
        // CekManagementProvider SPI, so this is the only way an HSM-held key can be used
        // for it. Registered before any key is handed out.
        NetHsmSecurityProvider.install()

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
            .checkList(KEY_USE_PROPERTY, false)
            .checkList(ALGORITHM_PROPERTY, false)

        // The two lists are disjoint, so a mismatched pair would silently publish nothing.
        val algorithm = model.get(Attributes.ALGORITHM_KEY, DEFAULT_ALGORITHM)
        val isEncryption = model.get(Attributes.KEY_USE, KeyUse.SIG.getSpecName())
            .equals(KeyUse.ENC.getSpecName(), ignoreCase = true)
        if (isEncryption && algorithm !in NetHsmAlgorithms.cekAlgorithms) {
            throw ComponentValidationException(
                "$algorithm cannot be used with key use 'enc'. Encryption keys must use one of " +
                    NetHsmAlgorithms.cekAlgorithms.joinToString(", "),
            )
        }
        if (!isEncryption && algorithm in NetHsmAlgorithms.cekAlgorithms) {
            throw ComponentValidationException("$algorithm is a key management algorithm; set key use to 'enc'")
        }

        warnIfSigningIsAmbiguous(model)

        val prefix = model.get(KEY_PREFIX_KEY, "")
        // NetHSM's ID schema is ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$; a prefix has to be a
        // prefix of something matching it, or discovery can never return anything.
        if (!KEY_PREFIX_PATTERN.matches(prefix)) {
            throw ComponentValidationException("Key ID prefix must match ${KEY_PREFIX_PATTERN.pattern}")
        }
    }

    /**
     * Keycloak signs with the *first* key a provider yields, so an active signing
     * component matching several keys picks one by id order -- not something an operator
     * would infer from the configuration.
     *
     * Warned at save time rather than per request, and not rejected: several keys under
     * one component is legitimate once it is passive, which is what rotation does with
     * the outgoing generation.
     */
    private fun warnIfSigningIsAmbiguous(model: ComponentModel) {
        val isSigning = !model.get(Attributes.KEY_USE, KeyUse.SIG.getSpecName())
            .equals(KeyUse.ENC.getSpecName(), ignoreCase = true)
        if (!isSigning || !model.get(Attributes.ACTIVE_KEY, true)) return

        val prefix = model.get(KEY_PREFIX_KEY, "")
        val algorithm = model.get(Attributes.ALGORITHM_KEY, DEFAULT_ALGORITHM)
        // A NetHSM unreachable at save time must not block saving the component.
        val matches = runCatching {
            discovery?.keys(prefix)
                ?.filter { algorithm in NetHsmAlgorithms.supportedAlgorithms(it) }
                ?.map { it.id }
                ?.sorted()
                .orEmpty()
        }.getOrDefault(emptyList())

        if (matches.size > 1) {
            log.warnf(
                "prefix '%s' matches %d keys that can serve %s (%s); '%s' will sign and the rest " +
                    "will only verify. Use one component per key generation, or make this one passive.",
                prefix, matches.size, algorithm, matches.joinToString(", "), matches.first(),
            )
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

        val KEY_USE_PROPERTY = ProviderConfigProperty(
            Attributes.KEY_USE,
            "Key use",
            "Whether these keys sign tokens ('sig') or decrypt inbound JWE ('enc'). Encrypting " +
                "to a client uses that client's public key and never involves the HSM.",
            ProviderConfigProperty.LIST_TYPE,
            KeyUse.SIG.getSpecName(),
            KeyUse.SIG.getSpecName(),
            KeyUse.ENC.getSpecName(),
        )

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
            // Key management, for key use 'enc'. RSA1_5 and ECDH-ES* are absent by
            // design -- see NetHsmAlgorithms and the README.
            JWEConstants.RSA_OAEP, JWEConstants.RSA_OAEP_256,
        )

        private val KEY_PREFIX_PATTERN = Regex("^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    }
}
