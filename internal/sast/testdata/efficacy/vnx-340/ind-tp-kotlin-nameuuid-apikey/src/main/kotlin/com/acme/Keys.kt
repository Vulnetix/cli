package com.acme

import java.util.UUID

class KeyService {
    fun newApiKey(owner: String): String {
~>        val apiKey = UUID.nameUUIDFromBytes(owner.toByteArray()).toString()
        repository.save(owner, apiKey)
        return apiKey
    }
}
