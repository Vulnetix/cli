package com.example.bank;

import android.content.SharedPreferences;
import android.os.Bundle;

public class Settings {
    void load(SharedPreferences prefs, Bundle state) {
        boolean dark = prefs.getBoolean("dark_mode", false);
        boolean onboarded = prefs.getBoolean("onboarding_seen", false);
        String lang = prefs.getString("language", "en");
        int scroll = state.getInt("scroll_position");
        boolean expanded = state.getBoolean("expanded");
    }
}
