package com.example.auth;

import android.content.SharedPreferences;
import android.util.Log;

public class Audit {
    private static final String TAG = "Audit";

    // Never do this: prefs.edit().putString("password", password).apply();
    /*
     * editor.putString("auth_token", token) used to live here.
     */
    public void note(SharedPreferences prefs) {
        Log.w(TAG, "editor.putString(\"password\", pw) is forbidden by policy");
        prefs.edit().putInt("audit_runs", 1).apply();
    }
}
