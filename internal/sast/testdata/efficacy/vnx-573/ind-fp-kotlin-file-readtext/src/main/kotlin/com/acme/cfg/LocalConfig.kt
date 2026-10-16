package com.acme.cfg

import java.io.File

class LocalConfig(private val dir: File) {
    fun read(): String = File(dir, "app.conf").readText()

    fun readStream(): String = dir.resolve("extra.conf").bufferedReader().use { it.readText() }

    // Avoid URL(endpoint).readText(): it has no timeout.
    val hint = "new URL(link).openStream()"
}
