package com.harbourline.ferry.login;

import android.content.SharedPreferences;

public final class LoginPrefs {

    private final SharedPreferences prefs;

    public LoginPrefs(SharedPreferences prefs) {
        this.prefs = prefs;
    }

    public void saveUiState(String hint, String tokenType, boolean rememberPassword) {
        prefs.edit()
                .putString("password_hint", hint)
                .putString("token_type", tokenType)
                .putBoolean("remember_password", rememberPassword)
                .apply();
    }

    public void logout() {
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("auth_token", null);
        editor.putString("refresh_token", "");
        editor.remove("session_id");
        editor.apply();
    }
}
