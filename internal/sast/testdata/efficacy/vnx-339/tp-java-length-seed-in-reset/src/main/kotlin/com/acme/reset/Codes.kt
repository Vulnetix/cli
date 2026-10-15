package com.acme.reset

import kotlin.random.Random

fun resetCode(email: String): Int {
~>    val rng = Random(email.length)
    return rng.nextInt(1000000)
}
