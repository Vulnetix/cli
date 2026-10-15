package com.acme.net;

import android.content.SharedPreferences;

final class TokenMeta {
    private static final String KEY_TOKEN_TYPE = "token_type";

    static void save(SharedPreferences prefs) {
        prefs.edit().putString(KEY_TOKEN_TYPE, "Bearer").apply();
        prefs.edit().putString("token", null).apply();
        prefs.edit().putString("password", "").apply();
    }
}
