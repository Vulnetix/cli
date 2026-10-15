package com.example.vault;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.fragment.app.Fragment;
import org.json.JSONObject;

public class ProfileFragment extends Fragment {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        SharedPreferences prefs = requireContext().getSharedPreferences("ui", Context.MODE_PRIVATE);
        boolean dark = prefs.getBoolean("dark_mode", false);
        int scroll = savedInstanceState != null ? savedInstanceState.getInt("scroll_y") : 0;
        prefs.edit().putBoolean("is_logged_in", true).apply();
    }

    void onProfile(JSONObject json) throws Exception {
        boolean admin = json.getBoolean("isAdmin");
        String role = json.getString("role");
    }
}
