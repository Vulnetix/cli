package com.harbourline.ferry.login;

import android.content.Context;
import android.preference.PreferenceManager;

public final class RememberMeStore {

    private static final String KEY_USERNAME = "username";
    private static final String KEY_PASSWORD = "password";

    private RememberMeStore() {}

    public static void remember(Context context, String username, String password) {
        PreferenceManager.getDefaultSharedPreferences(context)
                .edit()
                .putString(KEY_USERNAME, username)
~>                .putString(KEY_PASSWORD, password)
                .apply();
    }
}
