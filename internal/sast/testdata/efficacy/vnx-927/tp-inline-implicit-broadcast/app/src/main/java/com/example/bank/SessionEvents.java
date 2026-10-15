package com.example.bank;

import android.app.Activity;
import android.content.Intent;

public class SessionEvents extends Activity {
    void publish(String sessionId) {
~>        sendBroadcast(new Intent("com.example.bank.SESSION").putExtra("sid", sessionId));
    }
}
