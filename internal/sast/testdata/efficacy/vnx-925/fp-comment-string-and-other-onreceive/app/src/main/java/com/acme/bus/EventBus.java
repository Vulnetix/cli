package com.acme.bus;

import android.content.BroadcastReceiver;
import android.os.Message;

// A BroadcastReceiver is not used here; onReceive(Context, Intent) reads intent.getStringExtra("x")
public class EventBus {

    static final String HELP = "public void onReceive(Context c, Intent intent) { intent.getExtras(); }";

    public void onReceive(Message message) {
        handle(message.getData());
    }

    private void handle(Object data) {
    }
}
