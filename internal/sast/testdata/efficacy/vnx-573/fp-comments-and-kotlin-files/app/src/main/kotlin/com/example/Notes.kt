package com.example

import java.io.File

class Notes(private val dir: File) {
    // Do not use URL(x).readText(): it has no timeout
    private val tip = "new URL(link).openStream() blocks forever"

    fun load(name: String): String = File(dir, name).readText()

    fun reader(name: String): String = File(dir, name).bufferedReader().readText()
}
