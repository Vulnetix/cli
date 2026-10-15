package com.shop.otp

import kotlin.random.Random

class OtpIssuer {
~>    private val otpRng = Random(System.currentTimeMillis())

    fun issueOtp(): String {
        val otp = otpRng.nextInt(100000, 999999)
        return otp.toString()
    }
}
