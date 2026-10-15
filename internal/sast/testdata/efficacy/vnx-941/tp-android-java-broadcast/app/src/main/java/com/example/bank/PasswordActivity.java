package com.example.bank;

import android.app.Activity;
import android.content.Intent;

public class PasswordActivity extends Activity {

    void notifyChange(String phone, String newPassword) {
        Intent changed = new Intent();
        changed.setAction("com.example.bank.PASSWORD_CHANGED");
        changed.putExtra("phone", phone);
        changed.putExtra("password", newPassword);
~>        sendBroadcast(changed);
    }

    void notifyLogin(String user, String token) {
        Intent i = new Intent("com.example.bank.LOGIN");
        i.putExtra("user", user);
        i.putExtra("token", token);
~>        getApplicationContext().sendOrderedBroadcast(i, null);
    }
}
