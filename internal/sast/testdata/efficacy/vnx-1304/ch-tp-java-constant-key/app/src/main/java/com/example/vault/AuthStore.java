package com.example.vault;

import android.content.Context;
import android.content.SharedPreferences;

public final class AuthStore {
    private static final String PREFS = "auth";
    private static final String KEY_ROLE = "user_role";
    private final SharedPreferences sp;

    public AuthStore(Context ctx) {
        sp = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public String role() {
~>        return sp.getString(KEY_ROLE, "guest");
    }
}
