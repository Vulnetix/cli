package com.acme

import java.util.Random

class OtpGenerator {
~>    private val otpRandom = Random(System.nanoTime())

    fun nextOtp(): String = String.format("%06d", otpRandom.nextInt(1_000_000))
}
