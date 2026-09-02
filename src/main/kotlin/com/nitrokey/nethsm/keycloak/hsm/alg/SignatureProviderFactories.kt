package com.nitrokey.nethsm.keycloak.hsm.alg

import com.nitrokey.nethsm.keycloak.hsm.SignatureProviderPickerFactory
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.AsymmetricSignatureProvider
import org.keycloak.crypto.ECDSASignatureProvider
import org.keycloak.crypto.EdDSASignatureProvider
import org.keycloak.crypto.SignatureProvider
import org.keycloak.crypto.SignatureProviderFactory
import org.keycloak.models.KeycloakSession

/**
 * One factory per algorithm, each mirroring the delegate and JWK claim set that
 * Keycloak's own factory for that algorithm uses. Every class here must also be listed
 * in `META-INF/services/org.keycloak.crypto.SignatureProviderFactory`.
 */

abstract class RsaPickerFactory(algorithm: String) : SignatureProviderPickerFactory(
    algorithm,
    SignatureProviderFactory.RSA_PRIVATE_JWK_CLAIMS,
) {
    override fun createDelegate(session: KeycloakSession): SignatureProvider =
        AsymmetricSignatureProvider(session, algorithm)
}

abstract class EcPickerFactory(algorithm: String) : SignatureProviderPickerFactory(
    algorithm,
    SignatureProviderFactory.EC_PRIVATE_JWK_CLAIMS,
) {
    override fun createDelegate(session: KeycloakSession): SignatureProvider =
        ECDSASignatureProvider(session, algorithm)
}

abstract class OkpPickerFactory(algorithm: String) : SignatureProviderPickerFactory(
    algorithm,
    SignatureProviderFactory.OKP_PRIVATE_JWK_CLAIMS,
) {
    override fun createDelegate(session: KeycloakSession): SignatureProvider =
        EdDSASignatureProvider(session)
}

class RS256SignatureProviderFactory : RsaPickerFactory(Algorithm.RS256)
class RS384SignatureProviderFactory : RsaPickerFactory(Algorithm.RS384)
class RS512SignatureProviderFactory : RsaPickerFactory(Algorithm.RS512)

class PS256SignatureProviderFactory : RsaPickerFactory(Algorithm.PS256)
class PS384SignatureProviderFactory : RsaPickerFactory(Algorithm.PS384)
class PS512SignatureProviderFactory : RsaPickerFactory(Algorithm.PS512)

class ES256SignatureProviderFactory : EcPickerFactory(Algorithm.ES256)
class ES384SignatureProviderFactory : EcPickerFactory(Algorithm.ES384)
class ES512SignatureProviderFactory : EcPickerFactory(Algorithm.ES512)

class EdDSASignatureProviderFactory : OkpPickerFactory(Algorithm.EdDSA)
