package com.acme.io

fun finalize() {
    println("top-level cleanup hook")
}

class Handle(private val fd: Int) {
    protected fun finalize() {
        Posix.close(fd)
    }
}

// public fun finalize() would expose the finalizer
val note = "fun finalize() { }"
