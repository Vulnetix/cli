package com.acme;

import android.content.Context;
import android.content.Intent;

public class Notifier {
    public void publishToken(Context context, String token) {
        Intent intent = new Intent("com.acme.TOKEN_REFRESHED");
        intent.putExtra("token", token);
~>        context.sendBroadcast(intent);
    }
}
