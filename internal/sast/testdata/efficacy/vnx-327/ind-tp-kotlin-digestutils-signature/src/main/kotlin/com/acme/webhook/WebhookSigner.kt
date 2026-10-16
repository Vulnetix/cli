package com.acme.webhook

import org.apache.commons.codec.digest.DigestUtils

class WebhookSigner(private val sharedSecret: String) {

    fun sign(payload: String): String {
~>        val signature = DigestUtils.sha1Hex(sharedSecret + payload)
        return "sha1=$signature"
    }
}
