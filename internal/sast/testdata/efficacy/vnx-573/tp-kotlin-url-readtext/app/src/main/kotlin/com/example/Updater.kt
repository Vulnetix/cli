package com.example

import java.net.URL

class Updater(private val endpoint: String) {
~>    fun latest(): String = URL("$endpoint/latest").readText()

    fun download(): ByteArray {
        val url = URL(endpoint)
~>        return url.openStream().use { it.readBytes() }
    }
}
