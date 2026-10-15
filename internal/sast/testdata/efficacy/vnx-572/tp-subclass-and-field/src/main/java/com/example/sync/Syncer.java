package com.example.sync;

public class Syncer {
    static class PollThread extends Thread {
        @Override
        public void run() {
            poll();
        }

        void poll() {
        }
    }

    private Thread heartbeat;
    private PollThread poller;

    public void begin() {
        heartbeat = new Thread(this::beat);
~>        heartbeat.run();
        poller = new PollThread();
~>        this.poller.run();
~>        new PollThread().run();
    }

    private void beat() {
    }
}
