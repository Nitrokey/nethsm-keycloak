package com.nitrokey.nethsm.keycloak.hsm

import org.keycloak.keys.KeyProviderFactory

interface HsmKeyProviderFactory<T : HsmKeyProvider> : KeyProviderFactory<T>
