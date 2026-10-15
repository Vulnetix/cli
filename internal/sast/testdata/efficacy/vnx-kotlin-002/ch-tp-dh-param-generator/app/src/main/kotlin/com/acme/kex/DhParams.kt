package com.acme.kex

import java.security.AlgorithmParameterGenerator
import java.security.KeyPairGenerator
import javax.crypto.spec.DHParameterSpec

object DhParams {
    fun legacyGroup(): DHParameterSpec {
        val paramGen = AlgorithmParameterGenerator.getInstance("DH")
~>        paramGen.init(1024)
        val params = paramGen.generateParameters()
        return params.getParameterSpec(DHParameterSpec::class.java)
    }

    fun dsaDomain() = AlgorithmParameterGenerator.getInstance("DSA").apply {
~>        init(1024)
    }.generateParameters()

    fun keys(spec: DHParameterSpec) =
        KeyPairGenerator.getInstance("DH").apply { initialize(spec) }.generateKeyPair()
}
