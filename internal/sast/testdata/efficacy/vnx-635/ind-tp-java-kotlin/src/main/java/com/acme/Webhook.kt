package com.acme

class Webhook(private val secret: String) {
    fun accept(body: String, sig: String?): Boolean {
~>        // TODO: verify the HMAC signature of the payload
        return body.isNotEmpty()
    }
}
