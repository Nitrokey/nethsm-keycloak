/*
 * Derived from https://github.com/denniskniep/keycloak-hsm (Apache-2.0),
 * Copyright Dennis Kniep. Translated to Kotlin and adapted for Keycloak 26.x.
 */
package com.nitrokey.nethsm.keycloak.hsm

import org.keycloak.common.VerificationException
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.KeyWrapper
import org.keycloak.crypto.SignatureException
import org.keycloak.crypto.SignatureProvider
import org.keycloak.crypto.SignatureSignerContext
import org.keycloak.crypto.SignatureVerifierContext
import org.keycloak.models.KeycloakSession

/**
 * Routes each signing/verification call to the HSM when the realm's active key for
 * [algorithm] is an [HsmKeyWrapper], and to Keycloak's own [delegate] otherwise.
 *
 * Registering this for an algorithm is therefore safe even with no HSM key provider
 * configured: every call simply falls through to [delegate].
 */
class SignatureProviderPicker(
    private val session: KeycloakSession,
    private val algorithm: String,
    private val delegate: SignatureProvider,
) : SignatureProvider {

    private val keyType = keyTypeForAlgorithm(algorithm)

    override fun signer(): SignatureSignerContext {
        val key = session.keys().getActiveKey(session.context.realm, KeyUse.SIG, algorithm)
            ?: throw SignatureException("Active key for $algorithm not found")
        return (key as? HsmKeyWrapper)?.createSignatureSignerContext() ?: delegate.signer()
    }

    override fun signer(key: KeyWrapper): SignatureSignerContext {
        SignatureProvider.checkKeyForSignature(key, algorithm, keyType)
        return (key as? HsmKeyWrapper)?.createSignatureSignerContext() ?: delegate.signer(key)
    }

    override fun verifier(kid: String): SignatureVerifierContext {
        val key = session.keys().getKey(session.context.realm, kid, KeyUse.SIG, algorithm)
            ?: throw VerificationException("Key not found")
        return (key as? HsmKeyWrapper)?.createSignatureVerifierContext() ?: delegate.verifier(kid)
    }

    override fun verifier(key: KeyWrapper): SignatureVerifierContext {
        SignatureProvider.checkKeyForVerification(key, algorithm, keyType)
        return (key as? HsmKeyWrapper)?.createSignatureVerifierContext() ?: delegate.verifier(key)
    }

    override fun isAsymmetricAlgorithm(): Boolean = delegate.isAsymmetricAlgorithm()

    override fun close() = delegate.close()
}
