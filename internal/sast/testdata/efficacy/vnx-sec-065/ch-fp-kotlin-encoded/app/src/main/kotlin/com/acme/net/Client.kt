package com.acme.net

import java.util.Base64

class Client(private val user: String, private val pass: String) {
    private val encoded = Base64.getEncoder().encodeToString("$user:$pass".toByteArray())

    fun headers(): Map<String, String> = mapOf("Authorization" to "Basic $encoded")
    fun alt(): String = "Basic ${encoded}"
}
