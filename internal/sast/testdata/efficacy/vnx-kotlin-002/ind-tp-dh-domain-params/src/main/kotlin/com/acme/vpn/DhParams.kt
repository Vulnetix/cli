package com.acme.vpn

import java.security.AlgorithmParameterGenerator
import java.security.KeyPairGenerator
import javax.crypto.spec.DHParameterSpec

fun negotiationParameters(): DHParameterSpec {
    val paramGen = AlgorithmParameterGenerator.getInstance("DH")
~>    paramGen.init(1024)
    val params = paramGen.generateParameters()
    return params.getParameterSpec(DHParameterSpec::class.java)
}

fun peerKeyGenerator(): KeyPairGenerator {
    val kpg = KeyPairGenerator.getInstance("DiffieHellman")
~>    kpg.initialize(512)
    return kpg
}
