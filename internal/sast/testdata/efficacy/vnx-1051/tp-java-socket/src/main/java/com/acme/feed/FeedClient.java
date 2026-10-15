package com.acme.feed;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public class FeedClient {
~>    private static final String FEED_HOST = "10.8.0.14";

    public Socket open() throws IOException {
~>        return new Socket("10.8.0.15", 7001);
    }

    public InetAddress gateway() throws IOException {
~>        return InetAddress.getByName("10.8.0.1");
    }

    public void configure(ConnectionFactory factory) {
~>        factory.setHost("10.8.0.16");
    }
}
