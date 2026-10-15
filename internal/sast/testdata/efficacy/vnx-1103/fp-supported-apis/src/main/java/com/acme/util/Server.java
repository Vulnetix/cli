package com.acme.util;

import com.sun.net.httpserver.HttpServer;
import com.sun.management.OperatingSystemMXBean;
import com.sun.jna.Native;
import java.util.Base64;
import java.lang.invoke.VarHandle;
import java.net.InetSocketAddress;

public class Server {
    public void start() throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress(8080), 0);
        s.start();
        String enc = Base64.getEncoder().encodeToString(new byte[] {1, 2});
    }
}
