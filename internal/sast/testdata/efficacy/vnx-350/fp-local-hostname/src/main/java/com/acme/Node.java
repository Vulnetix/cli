package com.acme;

import java.net.InetAddress;

public class Node {
    String id() throws Exception {
        String host = InetAddress.getLocalHost().getHostName();
        if (host.startsWith("worker-")) {
            return host;
        }
        return "standalone";
    }
}
