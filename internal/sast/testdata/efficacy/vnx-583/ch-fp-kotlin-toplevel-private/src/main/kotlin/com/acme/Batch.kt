package com.acme

fun finalize() {
    println("top-level helper, not a finaliser")
}

class Batch {
    private fun finalize() {}
    internal fun finalizeBatch() {}
    fun finalize(reason: String) {}
}
