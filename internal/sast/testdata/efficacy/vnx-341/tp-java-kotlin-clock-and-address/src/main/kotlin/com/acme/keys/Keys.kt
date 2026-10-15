package com.acme.keys

fun issue(): String {
~>    val apiKey = "k" + System.nanoTime()
    return apiKey
}
