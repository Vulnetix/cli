package com.example.bank;

import android.content.Context;
import android.content.Intent;

public class PasswordSync {
    private final Context context;

    PasswordSync(Context context) { this.context = context; }

    void announce(String phone, String newPassword) {
        Intent update = new Intent();
        update.setAction("com.example.bank.PASSWORD_CHANGED");
        update.putExtra("phone", phone);
        update.putExtra("password", newPassword);
~>        context.sendBroadcast(update);
    }

    void notifyLogin(String token) {
        Intent i = new Intent(ACTION_LOGIN);
        i.putExtra("token", token);
~>        context.sendOrderedBroadcast(i, null);
    }

    static final String ACTION_LOGIN = "com.example.bank.LOGIN";
}
