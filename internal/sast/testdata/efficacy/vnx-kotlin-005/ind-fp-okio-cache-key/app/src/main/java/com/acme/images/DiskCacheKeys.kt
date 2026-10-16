package com.acme.images

import okio.ByteString.Companion.encodeUtf8
import java.io.File

class DiskCacheKeys(private val cacheDir: File) {
    fun key(url: String): String = url.encodeUtf8().md5().hex()

    fun fileFor(url: String): File = File(cacheDir, url.encodeUtf8().sha1().hex() + ".img")
}
