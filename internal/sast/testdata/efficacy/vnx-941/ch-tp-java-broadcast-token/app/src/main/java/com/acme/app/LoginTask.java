package com.acme.app;

import android.content.Context;
import android.content.Intent;

public class LoginTask {
    void onLoggedIn(Context context, String sessionToken) {
        Intent intent = new Intent("com.acme.app.ACTION_LOGIN");
        intent.putExtra("session", sessionToken);
~>        context.sendBroadcast(intent);
    }
}
