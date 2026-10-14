package com.example.auth;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.security.crypto.EncryptedSharedPreferences;

public class VaultStore {
    private final SharedPreferences securePrefs;

    public VaultStore(Context context, androidx.security.crypto.MasterKey key) throws Exception {
        securePrefs = EncryptedSharedPreferences.create(context, "vault", key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
    }

    public void saveToken(String token) {
        SharedPreferences.Editor editor = securePrefs.edit();
        editor.putString("auth_token", token);
        editor.apply();
    }
}
