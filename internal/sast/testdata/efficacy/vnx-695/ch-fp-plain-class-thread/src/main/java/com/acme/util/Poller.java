package com.acme.util;

import java.io.FileInputStream;
import java.net.Socket;

public class Poller {

    public synchronized void start() throws Exception {
        Thread t = new Thread(this::poll);
        t.start();
        try (FileInputStream in = new FileInputStream("/etc/hosts")) {
            in.read();
        }
        new Socket("localhost", 80).close();
    }

    private void poll() {
    }
}
