import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

val key = SecretKeySpec(System.getenv("ROTATE_KEY").toByteArray(), "AES")
~>val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
cipher.init(Cipher.ENCRYPT_MODE, key)
