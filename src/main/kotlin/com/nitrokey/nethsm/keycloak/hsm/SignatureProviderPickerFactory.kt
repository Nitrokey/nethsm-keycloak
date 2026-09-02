package com.nitrokey.nethsm.keycloak.hsm

import org.keycloak.crypto.SignatureProvider
import org.keycloak.crypto.SignatureProviderFactory
import org.keycloak.models.KeycloakSession

/**
 * Base for factories that shadow one of Keycloak's built-in [SignatureProviderFactory]s.
 *
 * The override works by registering the *same* provider id (the algorithm name, e.g.
 * "RS256") with a higher [order]. Deploying a same-id provider used to be enough on its
 * own; that broke in Keycloak 21, and `order()` is now the supported mechanism.
 *
 * [privateJwkClaims] is passed in rather than exposed as an abstract `val` on purpose:
 * a Kotlin property named `jwkPrivateKeyClaims` compiles to a `getJwkPrivateKeyClaims()`
 * getter, which collides with the identically-named Java interface method
 * ("inherited platform declarations clash").
 */
abstract class SignatureProviderPickerFactory(
    protected val algorithm: String,
    private val privateJwkClaims: Set<String>,
) : SignatureProviderFactory {

    /** The built-in provider to fall through to for non-HSM keys. */
    protected abstract fun createDelegate(session: KeycloakSession): SignatureProvider

    override fun create(session: KeycloakSession): SignatureProvider =
        SignatureProviderPicker(session, algorithm, createDelegate(session))

    override fun getId(): String = algorithm

    override fun getJwkPrivateKeyClaims(): Set<String> = privateJwkClaims

    override fun order(): Int = HSM_PICKER_ORDER

    private companion object {
        /** Built-in factories use the default order of 0. */
        const val HSM_PICKER_ORDER = 1
    }
}
