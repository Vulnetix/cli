package com.acme.keys

import java.util.UUID

fun issue(user: String): String {
~>    val apiKey = UUID.nameUUIDFromBytes(user.toByteArray()).toString()
    return apiKey
}
