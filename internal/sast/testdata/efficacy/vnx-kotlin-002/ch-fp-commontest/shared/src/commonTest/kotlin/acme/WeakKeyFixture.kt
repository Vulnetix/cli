package acme

import java.security.KeyPairGenerator

class WeakKeyFixture {
    fun tinyKeyForSpeed() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(512)
        kpg.generateKeyPair()
    }
}
