package com.acme;

import java.net.ServerSocket;
import java.net.Socket;

public class AdminConsole implements Runnable {
    private final int adminPort;

    public void run() {
~>      try (ServerSocket adminSocket = new ServerSocket(adminPort)) {
            while (true) {
                Socket s = adminSocket.accept();
                handleCommand(s);
            }
        } catch (Exception e) {
            log.error("admin console stopped", e);
        }
    }
}
