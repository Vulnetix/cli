package com.acme

class Safe(private val store: Store) {
    fun userId(token: String): String? = store.lookup(token)?.userId

    fun parse(s: String): Int = try { s.toInt() } catch (e: NumberFormatException) { 0 }
}
