package com.example;

import android.content.Intent;

public class Router {
    void route(Intent intent) {
        // prefs.getBoolean("isLoggedIn", false) must not be used here
        boolean fromLink = intent.getBooleanExtra("is_admin", false);
        String s = "prefs.getBoolean(\"is_admin\")";
    }
}
