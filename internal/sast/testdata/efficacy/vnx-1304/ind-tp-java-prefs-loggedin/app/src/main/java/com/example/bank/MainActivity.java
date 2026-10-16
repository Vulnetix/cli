package com.example.bank;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        SharedPreferences prefs = getSharedPreferences("bank", MODE_PRIVATE);
~>        boolean loggedIn = prefs.getBoolean("isLoggedIn", false);
        if (loggedIn) {
            showAccounts();
        }
    }
}
