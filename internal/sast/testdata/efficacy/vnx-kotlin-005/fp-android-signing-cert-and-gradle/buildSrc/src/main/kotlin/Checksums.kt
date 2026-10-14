import java.io.File
import java.security.MessageDigest

fun File.md5Sidecar(): String = MessageDigest.getInstance("MD5").digest(readBytes()).joinToString("") { "%02x".format(it) }
