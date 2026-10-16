package com.example.sec

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences

class Secure(ctx: Context, masterKey: androidx.security.crypto.MasterKey) {
    private val enc = EncryptedSharedPreferences.create(
        ctx, "secure", masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun hint(): Boolean {
        return enc.getBoolean("isLoggedIn", false)
    }
}
