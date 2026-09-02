package com.nitrokey.nethsm.keycloak.hsm

import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.KeyType

/**
 * Maps a JOSE algorithm to the Keycloak [KeyType] that `SignatureProvider.checkKeyFor*`
 * expects.
 *
 * Deliberately not `JavaAlgorithm.getKeyType`, which takes a *Java* algorithm name
 * ("RSA", "EC", "EdDSA"), not a JOSE one. Also note EdDSA maps to OKP, not EC -- the
 * upstream keycloak-hsm `AlgorithmUtils` returns EC here, which would make
 * `checkKeyForSignature` reject a correctly-typed Ed25519 key.
 */
internal fun keyTypeForAlgorithm(algorithm: String): String = when (algorithm) {
    Algorithm.RS256, Algorithm.RS384, Algorithm.RS512,
    Algorithm.PS256, Algorithm.PS384, Algorithm.PS512,
    -> KeyType.RSA

    Algorithm.ES256, Algorithm.ES384, Algorithm.ES512 -> KeyType.EC

    Algorithm.EdDSA, Algorithm.Ed25519, Algorithm.Ed448 -> KeyType.OKP

    else -> throw UnsupportedOperationException("$algorithm cannot be mapped to a Keycloak KeyType")
}
