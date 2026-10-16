package com.acme;

import android.content.Intent;

public class Pw extends android.app.Service {
    void notifyChange(String newPassword) {
        Intent changed = new Intent("com.example.PASSWORD_CHANGED");
        changed.putExtra("password", newPassword);
~>        sendBroadcast(changed);
    }
}
