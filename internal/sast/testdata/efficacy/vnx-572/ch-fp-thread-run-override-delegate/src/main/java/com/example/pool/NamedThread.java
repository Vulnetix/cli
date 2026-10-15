package com.example.pool;

public class NamedThread extends Thread {
    private final Runnable body;

    public NamedThread(Runnable body, String name) {
        super(name);
        this.body = body;
    }

    @Override
    public void run() {
        try {
            body.run();
        } finally {
            cleanup();
        }
    }

    private void cleanup() {
    }

    public static NamedThread launch(Runnable r) {
        NamedThread t = new NamedThread(r, "worker");
        t.start();
        return t;
    }
}
