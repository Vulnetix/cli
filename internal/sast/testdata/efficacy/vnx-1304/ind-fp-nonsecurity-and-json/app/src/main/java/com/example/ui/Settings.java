package com.example.ui;

import android.content.SharedPreferences;
import org.json.JSONObject;

public class Settings {
    void load(SharedPreferences prefs, JSONObject response) throws Exception {
        boolean dark = prefs.getBoolean("dark_mode", false);
        String lang = prefs.getString("language", "en");
        int scroll = prefs.getInt("scroll_position", 0);
        boolean authenticated = response.getBoolean("authenticated");
        String role = response.getString("role");
    }
}
