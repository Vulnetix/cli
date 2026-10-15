package com.acme.net;

import java.net.InetAddress;
import java.net.Socket;

public class Networks {
    private static final String PRIVATE_RANGE = "10.0.0.0/8";
    private static final String SCHEMA_VERSION = "2.4.0.1";
    private static final String DESCRIPTION = "Talks to 10.8.0.14 in the staging lab";

    public Socket open(Config config) throws Exception {
        return new Socket(config.feedHost(), config.feedPort());
    }

    public InetAddress loopback() throws Exception {
        return InetAddress.getByName("127.0.0.1");
    }

    public String zipCode() {
        return "zip=10.8.0.14";
    }
}
