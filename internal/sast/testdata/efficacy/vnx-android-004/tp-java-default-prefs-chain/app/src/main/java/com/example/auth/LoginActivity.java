package com.example.auth;

import android.app.Activity;
import android.preference.PreferenceManager;
import android.widget.EditText;

public class LoginActivity extends Activity {
    private EditText passwordField;

    private void rememberCredentials(String user) {
        String pw = passwordField.getText().toString();
~>        PreferenceManager.getDefaultSharedPreferences(this).edit().putString("password", pw).commit();
~>        getSharedPreferences("creds", MODE_PRIVATE).edit().putString("user_secret", user + ":" + pw).apply();
    }
}
