package com.acme.otp

import kotlin.random.Random

object Otp {
~>    private val rng = Random(42)

    fun newOtp(): String = rng.nextInt(1000000).toString().padStart(6, '0')
}
