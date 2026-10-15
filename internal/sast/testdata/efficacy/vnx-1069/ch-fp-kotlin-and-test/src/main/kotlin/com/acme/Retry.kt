package com.acme

fun attempt(block: () -> Unit) {
    try { block() } catch (e: Exception) {}
}
