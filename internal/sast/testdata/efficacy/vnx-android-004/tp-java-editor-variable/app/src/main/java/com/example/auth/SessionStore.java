package com.example.auth;

import android.content.Context;
import android.content.SharedPreferences;

public class SessionStore {
    private static final String PREFS = "session";
    private static final String KEY_PASSWORD = "pwd";
    private final SharedPreferences prefs;
    private SharedPreferences.Editor mEditor;

    public SessionStore(Context context) {
        prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        mEditor = prefs.edit();
    }

    public void save(LoginResponse response, String username, String password) {
        SharedPreferences.Editor editor = prefs.edit();
~>        editor.putString("auth_token", response.getToken());
~>        editor.putString(KEY_PASSWORD, password);
        editor.putString("username", username);
        editor.apply();
    }

    public void saveRefresh(String refreshToken) {
~>        mEditor.putString("refresh", refreshToken).commit();
    }

    public void saveMultiline(String apiKey) {
        SharedPreferences.Editor e = prefs.edit();
~>        e.putString(
                "api_key",
                apiKey);
        e.apply();
    }
}
