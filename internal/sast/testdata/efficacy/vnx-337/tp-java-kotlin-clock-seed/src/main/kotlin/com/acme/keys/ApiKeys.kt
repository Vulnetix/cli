package com.acme.keys

import kotlin.random.Random

object ApiKeys {
~>    private val rng = Random(System.currentTimeMillis())

    fun newApiKey(): String = rng.nextLong().toString(16)
}
