package com.example.avatar

import java.net.URL

class AvatarCache(private val cdn: String) {
    fun download(user: String): ByteArray {
        val src = URL("$cdn/avatars/$user.png")
~>        return src.readBytes()
    }

    fun headline(page: String): String =
~>        URL(page).openStream().bufferedReader().use { it.readLine() }
}
