package com.acme;
public class Listener {
    void run() throws Exception {
~>        ServerSocket server = new ServerSocket(9000);
        while (true) { handle(server.accept()); }
    }
}
