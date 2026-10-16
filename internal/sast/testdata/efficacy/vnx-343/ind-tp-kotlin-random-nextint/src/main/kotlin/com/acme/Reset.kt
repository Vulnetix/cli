package com.acme

import kotlin.random.Random

class ResetCodes(private var previousCode: Int) {
    fun next(): Int {
~>        val resetCode = previousCode + Random.nextInt(1, 250)
        previousCode = resetCode
        return resetCode
    }
}
