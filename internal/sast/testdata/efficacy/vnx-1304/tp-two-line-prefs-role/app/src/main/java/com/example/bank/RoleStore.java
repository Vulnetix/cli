package com.example.bank;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

public class RoleStore {
    public static String role(Context ctx) {
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
~>        return sp.getString("user_role", "customer");
    }

    public static boolean premium(Context ctx) {
        return ctx.getSharedPreferences("billing", 0)
~>            .getBoolean("isPremium", false);
    }
}
