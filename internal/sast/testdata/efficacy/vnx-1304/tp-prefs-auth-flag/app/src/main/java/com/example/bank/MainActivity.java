package com.example.bank;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        SharedPreferences prefs = getSharedPreferences("bank", MODE_PRIVATE);
~>        boolean loggedIn = prefs.getBoolean("isLoggedIn", false);
        if (loggedIn) {
            showAccounts();
        } else {
            showLogin();
        }
    }
}
