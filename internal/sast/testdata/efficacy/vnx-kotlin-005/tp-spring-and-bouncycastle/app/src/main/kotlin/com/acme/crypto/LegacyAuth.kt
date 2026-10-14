package com.acme.crypto

import org.bouncycastle.crypto.digests.MD5Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.util.DigestFactory
import org.springframework.util.DigestUtils

class LegacyAuth {
    fun storedHash(password: String): String =
~>        DigestUtils.md5DigestAsHex(password.toByteArray())

~>    fun raw(bytes: ByteArray): ByteArray = DigestUtils.md5Digest(bytes)

    fun bc(data: ByteArray): ByteArray {
~>        val digest = MD5Digest()
        digest.update(data, 0, data.size)
        val out = ByteArray(digest.digestSize)
        digest.doFinal(out, 0)
        return out
    }

~>    fun bcSha1() = SHA1Digest()

~>    fun factory() = DigestFactory.createSHA1()
}

class LegacySigner {
~>    fun signer() = org.bouncycastle.crypto.signers.RSADigestSigner(org.bouncycastle.crypto.digests.SHA1Digest())
}
