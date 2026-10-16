package com.acme.release

import java.net.URL

class ReleaseClient(private val endpoint: String) {
~>    fun latest(): String = URL("$endpoint/releases/latest").readText()

    fun changelog(tag: String): String {
        val u = URL("$endpoint/releases/$tag/notes")
~>        return u.readText()
    }
}
