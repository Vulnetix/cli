package com.acme.feed;

import java.net.ServerSocket;
import java.net.Socket;

public class FeedServer {
    public void serve() throws Exception {
~>        ServerSocket server = new ServerSocket(9000);
        while (true) {
            Socket c = server.accept();
            handle(c);
        }
    }
}
