import java.io.File
import java.security.KeyPairGenerator
import java.util.Base64

val kpg = KeyPairGenerator.getInstance("RSA")
~>kpg.initialize(1024)
val pair = kpg.generateKeyPair()
File("deploy.key").writeText(Base64.getEncoder().encodeToString(pair.private.encoded))
