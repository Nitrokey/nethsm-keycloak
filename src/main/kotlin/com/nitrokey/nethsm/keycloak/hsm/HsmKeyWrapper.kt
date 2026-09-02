package com.nitrokey.nethsm.keycloak.hsm

import org.keycloak.crypto.KeyWrapper
import org.keycloak.crypto.SignatureSignerContext
import org.keycloak.crypto.SignatureVerifierContext

/**
 * A [KeyWrapper] whose private key lives in an HSM and is never materialised in the JVM.
 *
 * [SignatureProviderPicker] detects these by type, so the subclass identity has to survive
 * all the way from the key provider to the signing call. Note that [KeyWrapper.cloneKey]
 * hardcodes `new KeyWrapper()` and therefore erases that identity; in Keycloak 26.7.3 the
 * only caller is `oid4vc.issuance.signing.AbstractCredentialSigner`, so OIDC and SAML are
 * unaffected but OID4VC credential issuance will not route through the HSM.
 */
abstract class HsmKeyWrapper : KeyWrapper() {

    abstract fun createSignatureSignerContext(): SignatureSignerContext

    abstract fun createSignatureVerifierContext(): SignatureVerifierContext
}
