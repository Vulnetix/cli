package com.acme.login;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

public final class Session {
    private static final String KEY_PASSWORD = "user_password";

    public static void remember(Context ctx, String user, String password) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        prefs.edit()
                .putString("user_name", user)
~>                .putString(KEY_PASSWORD, password)
                .apply();
    }
}
