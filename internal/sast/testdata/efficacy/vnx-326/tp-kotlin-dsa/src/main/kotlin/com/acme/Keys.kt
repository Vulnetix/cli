package com.acme

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

fun dsaPair() {
    val gen = KeyPairGenerator.getInstance("DSA")
~>    gen.initialize(1024)
    val ec = KeyPairGenerator.getInstance("EC")
~>    ec.initialize(ECGenParameterSpec("prime192v1"))
}
