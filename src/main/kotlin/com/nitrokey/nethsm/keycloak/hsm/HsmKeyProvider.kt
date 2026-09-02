package com.nitrokey.nethsm.keycloak.hsm

import org.keycloak.crypto.KeyWrapper
import org.keycloak.keys.KeyProvider
import java.util.stream.Stream

/** A [KeyProvider] that only ever hands out [HsmKeyWrapper]s. */
abstract class HsmKeyProvider : KeyProvider {

    abstract fun getHsmKeysStream(): Stream<out HsmKeyWrapper>

    override fun getKeysStream(): Stream<KeyWrapper> = getHsmKeysStream().map<KeyWrapper> { it }
}
