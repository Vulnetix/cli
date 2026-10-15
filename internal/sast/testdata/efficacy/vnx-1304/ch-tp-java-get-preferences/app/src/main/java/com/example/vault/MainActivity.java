package com.example.vault;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
~>        boolean admin = getPreferences(Context.MODE_PRIVATE).getBoolean("isAdmin", false);
        if (admin) {
            showAdminPanel();
        }
    }
}
