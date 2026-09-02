package com.nitrokey.nethsm.keycloak.client

import org.keycloak.Config
import java.time.Duration

/**
 * The global NetHSM connection profile, read once at factory init from
 * `spi-keys--nethsm--*` in `keycloak.conf` (or the matching `KC_SPI_KEYS__NETHSM__*`
 * environment variables).
 *
 * Connection and credentials are deliberately global rather than per-realm: realms
 * differ only in which key ids they claim, which is component config on the provider
 * instance. Putting the passphrase here keeps it out of the realm database and lets it
 * come from a container secret via the environment.
 */
class NetHsmConfig(
    /** API base URLs including `/api/v1`. More than one = cluster members, tried in turn. */
    val urls: List<String>,
    /** NetHSM user id with the Operator role. Administrator is not needed: we never generate keys. */
    val username: String,
    val passphrase: String,
    /** Lowercase hex SHA-256 fingerprints of accepted server certificates. Empty = use the JVM truststore. */
    val tlsFingerprints: Set<String>,
    /** Disables certificate verification entirely. Development only. */
    val tlsInsecure: Boolean,
    val timeout: Duration,
    val retries: Int,
    val retryDelay: Duration,
    /**
     * Time allowed to *establish* a connection, separate from [timeout] and much shorter.
     *
     * A NetHSM that drops packets rather than refusing costs the full connect timeout on
     * every attempt, and every attempt happens on a Keycloak request thread. Keeping this
     * small bounds how long an outage can hold those threads: the worst case is
     * `(retries + 1) x urls x this`, not the same product of [timeout].
     */
    val connectTimeout: Duration = Duration.ofSeconds(3),
    /** Upper bound on concurrent connections to NetHSM, shared by every realm. */
    val maxConnections: Int,
    /** How long discovered key metadata stays usable, including while NetHSM is unreachable. */
    val discoveryCache: Duration,
) {
    companion object {
        const val URL = "url"
        const val USERNAME = "username"
        const val PASSPHRASE = "passphrase"
        const val TLS_FINGERPRINTS = "tls-fingerprints"
        const val TLS_INSECURE = "tls-insecure"
        const val TIMEOUT_SECONDS = "timeout-seconds"
        const val CONNECT_TIMEOUT_SECONDS = "connect-timeout-seconds"
        const val RETRIES = "retries"
        const val RETRY_DELAY_MS = "retry-delay-ms"
        const val MAX_CONNECTIONS = "max-connections"
        const val DISCOVERY_CACHE_SECONDS = "discovery-cache-seconds"

        /**
         * Returns null when no `url` is configured, which is the normal state for a
         * Keycloak that has the jar deployed but no NetHSM. The factory then stays
         * registered but inert rather than failing startup.
         */
        fun from(scope: Config.Scope): NetHsmConfig? {
            val urls = scope.getArray(URL)?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
            if (urls.isEmpty()) return null

            val username = scope.get(USERNAME)
                ?: error("spi-keys--nethsm--url is set but --username is missing")
            val passphrase = scope.get(PASSPHRASE)
                ?: error("spi-keys--nethsm--url is set but --passphrase is missing")

            val fingerprints = scope.getArray(TLS_FINGERPRINTS)
                ?.map { it.trim().lowercase().replace(":", "") }
                ?.filter { it.isNotEmpty() }
                .orEmpty()
                .toSet()

            val insecure = scope.getBoolean(TLS_INSECURE, false)
            require(!(insecure && fingerprints.isNotEmpty())) {
                "$TLS_INSECURE and $TLS_FINGERPRINTS are mutually exclusive"
            }

            return NetHsmConfig(
                urls = urls,
                username = username,
                passphrase = passphrase,
                tlsFingerprints = fingerprints,
                tlsInsecure = insecure,
                timeout = Duration.ofSeconds(scope.getLong(TIMEOUT_SECONDS, 10L)),
                connectTimeout = Duration.ofSeconds(scope.getLong(CONNECT_TIMEOUT_SECONDS, 3L)),
                retries = scope.getInt(RETRIES, 2),
                retryDelay = Duration.ofMillis(scope.getLong(RETRY_DELAY_MS, 200L)),
                maxConnections = scope.getInt(MAX_CONNECTIONS, 20),
                discoveryCache = Duration.ofSeconds(scope.getLong(DISCOVERY_CACHE_SECONDS, 300L)),
            )
        }
    }
}
