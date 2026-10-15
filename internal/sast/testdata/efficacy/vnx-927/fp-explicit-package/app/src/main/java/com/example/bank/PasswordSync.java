package com.example.bank;

import android.content.Context;
import android.content.Intent;

public class PasswordSync {
    void announce(Context context, String phone) {
        Intent update = new Intent("com.example.bank.PASSWORD_CHANGED");
        update.setPackage(context.getPackageName());
        update.putExtra("phone", phone);
        context.sendBroadcast(update);

        Intent other = new Intent();
        other.setComponent(new android.content.ComponentName(context, Receiver.class));
        context.sendBroadcast(other);

        Intent third = new Intent("com.example.bank.X").setClassName("com.example.bank", "com.example.bank.Receiver");
        context.sendBroadcast(third);
    }
}
