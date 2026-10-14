import java.security.MessageDigest

plugins {
    `maven-publish`
}

// Maven repositories still expect .md5 and .sha1 sidecar checksums.
tasks.register("checksums") {
    doLast {
        fileTree("build/libs").forEach { jar ->
            val md5 = MessageDigest.getInstance("MD5").digest(jar.readBytes())
            val sha1 = MessageDigest.getInstance("SHA-1").digest(jar.readBytes())
            file("${jar.path}.md5").writeText(md5.joinToString("") { "%02x".format(it) })
            file("${jar.path}.sha1").writeText(sha1.joinToString("") { "%02x".format(it) })
        }
    }
}
