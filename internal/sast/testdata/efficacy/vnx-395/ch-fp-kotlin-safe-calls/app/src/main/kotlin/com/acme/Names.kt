package com.acme

class Names(private val repo: Repo) {
    fun display(id: Long): String = repo.find(id)?.displayName ?: "anonymous"

    fun parse(s: String): Int = try {
        s.toInt()
    } catch (e: NumberFormatException) {
        0
    }

    val hint = "catch (e: NullPointerException)"
}
