package com.northwind.payroll.auth;

import android.content.Context;
import android.content.SharedPreferences;

public final class SessionRepository {

    private static final String PREFS = "payroll_session";
    private static final String KEY_ACCESS_TOKEN = "access_token";

    private final SharedPreferences prefs;

    public SessionRepository(Context context) {
        this.prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public void save(LoginResponse response) {
        SharedPreferences.Editor editor = prefs.edit();
~>        editor.putString(KEY_ACCESS_TOKEN, response.getAccessToken());
~>        editor.putString("refresh_token", response.getRefreshToken());
        editor.putString("display_name", response.getDisplayName());
        editor.putLong("expires_at", response.getExpiresAt());
        editor.apply();
    }
}
