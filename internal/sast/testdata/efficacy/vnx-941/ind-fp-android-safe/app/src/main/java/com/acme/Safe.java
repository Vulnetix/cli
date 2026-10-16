package com.acme;

import android.content.Intent;

public class Safe extends android.app.Service {
    void a(String pw) {
        Intent i = new Intent("com.example.PW");
        i.setPackage(getPackageName());
        i.putExtra("password", pw);
        sendBroadcast(i);
    }
    void b(String pw) {
        Intent i = new Intent("com.example.PW");
        i.putExtra("password", pw);
        sendBroadcast(i, "com.acme.permission.RECEIVE_PW");
    }
    void c() {
        Intent i = new Intent("com.example.PING");
        sendBroadcast(i);
    }
    void d(String pw) {
        Intent i = new Intent(this, Recv.class);
        i.putExtra("password", pw);
        sendBroadcast(i);
    }
}
