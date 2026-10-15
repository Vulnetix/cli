package com.acme.storage

import java.security.MessageDigest
import java.util.Base64

class Uploader(private val http: HttpClient) {
    fun put(key: String, body: ByteArray) {
        // The storage API requires a Content-MD5 header for transfer integrity.
        val md5 = MessageDigest.getInstance("MD5").digest(body)
        http.put("/objects/$key") {
            header("Content-MD5", Base64.getEncoder().encodeToString(md5))
            setBody(body)
        }
    }
}
