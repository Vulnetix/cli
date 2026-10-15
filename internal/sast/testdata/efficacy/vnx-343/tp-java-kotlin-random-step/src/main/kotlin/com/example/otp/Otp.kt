package com.example.otp

import kotlin.random.Random

class OtpIssuer(private var lastOtp: Int) {
    fun issue(): Int {
~>        val otp = lastOtp + Random.nextInt(1, 50)
        lastOtp = otp
        return otp
    }
}
