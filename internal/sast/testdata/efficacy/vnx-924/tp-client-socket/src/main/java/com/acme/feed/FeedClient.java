package com.acme.feed;

import java.io.OutputStream;
import java.net.Socket;

public class FeedClient {
    public void send(String host, int port, byte[] order) throws Exception {
~>        try (Socket s = new Socket(host, port)) {
            OutputStream out = s.getOutputStream();
            out.write(order);
        }
    }
}
