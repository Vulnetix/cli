package com.acme.ops;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Console {
    public void start() throws IOException {
        ServerSocket adminSocket =
~>                new ServerSocket(9443);
        while (true) {
            Socket s = adminSocket.accept();
            handle(s);
        }
    }
}
