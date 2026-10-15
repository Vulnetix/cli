@file:DependsOn("commons-codec:commons-codec:1.16.0")

import org.apache.commons.codec.digest.DigestUtils

val users = listOf("alice" to "pw1", "bob" to "pw2")
for ((name, pw) in users) {
~>    println("$name:" + DigestUtils.sha1Hex(pw))
}
