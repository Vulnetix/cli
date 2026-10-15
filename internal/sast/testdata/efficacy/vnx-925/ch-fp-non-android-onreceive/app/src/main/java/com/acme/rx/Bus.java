package com.acme.rx;

public class Bus implements Listener {
    // not an Android receiver; references BroadcastReceiver only in a comment
    @Override
    public void onReceive(Message message) {
        String body = message.getData();
        handle(body);
    }
}
