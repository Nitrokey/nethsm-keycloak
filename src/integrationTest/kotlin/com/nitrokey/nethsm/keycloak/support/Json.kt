package com.nitrokey.nethsm.keycloak.support

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper

/** Tree-only JSON access, so no Kotlin data class ever meets Jackson without its module. */
object Json {
    private val mapper = ObjectMapper()

    fun read(bytes: ByteArray): JsonNode = mapper.readTree(bytes)

    fun read(text: String): JsonNode = mapper.readTree(text)

    fun write(value: Any): String = mapper.writeValueAsString(value)
}
