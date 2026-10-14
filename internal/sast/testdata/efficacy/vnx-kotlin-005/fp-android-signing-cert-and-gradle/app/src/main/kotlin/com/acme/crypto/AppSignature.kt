package com.acme.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import java.security.MessageDigest

object AppSignature {
    // The key hash the identity provider's console asks for.
    fun keyHashes(context: Context): List<String> {
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        return info.signingInfo.apkContentsSigners.map { signature ->
            val md = MessageDigest.getInstance("SHA")
            md.update(signature.toByteArray())
            Base64.encodeToString(md.digest(), Base64.NO_WRAP)
        }
    }
}
