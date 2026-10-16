package com.acme.storage

import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Base64

class S3Uploader {
    fun put(presigned: URL, body: ByteArray) {
        val conn = presigned.openConnection() as HttpURLConnection
        conn.requestMethod = "PUT"
        conn.doOutput = true
        val contentMd5 = Base64.getEncoder().encodeToString(MessageDigest.getInstance("MD5").digest(body))
        conn.setRequestProperty("Content-MD5", contentMd5)
        conn.outputStream.use { it.write(body) }
        check(conn.responseCode == 200)
    }
}
