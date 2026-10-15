package com.acme.feed;

import java.net.ServerSocket;

public class FeedServerTest {
    // new Socket(host, port) sends cleartext
    void start() throws Exception {
        ServerSocket server = new ServerSocket(0);
    }
}
