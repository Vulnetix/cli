package com.example.mail;

import java.util.Queue;

public class Outbox {
    private final Queue<String> pending;

    public Outbox(Queue<String> pending) {
        this.pending = pending;
    }

    public void flush() {
        var sender = new Thread() {
            @Override
            public void run() {
                while (!pending.isEmpty()) {
                    deliver(pending.poll());
                }
            }
        };
        sender.setDaemon(true);
~>        sender.run();
    }

    private void deliver(String msg) {
    }
}
