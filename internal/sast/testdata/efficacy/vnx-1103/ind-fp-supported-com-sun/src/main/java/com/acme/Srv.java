package com.acme;

import com.sun.net.httpserver.HttpServer;
import com.sun.management.OperatingSystemMXBean;
import java.util.Base64;
import java.net.InetSocketAddress;

public class Srv {
    HttpServer start() throws Exception {
        return HttpServer.create(new InetSocketAddress(8080), 0);
    }
    String enc(byte[] b) { return Base64.getEncoder().encodeToString(b); }
}
