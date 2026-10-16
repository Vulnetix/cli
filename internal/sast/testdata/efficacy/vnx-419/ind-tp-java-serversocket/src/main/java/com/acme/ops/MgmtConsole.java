package com.acme.ops;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;

public class MgmtConsole {
    private final OpsConfig config;

    public MgmtConsole(OpsConfig config) { this.config = config; }

    public void start() throws IOException {
~>        ServerSocket mgmtServer = new ServerSocket(config.getMgmtPort());
        new Thread(() -> acceptLoop(mgmtServer)).start();

~>        HttpServer adminHttp = HttpServer.create(new InetSocketAddress(config.getAdminPort()), 0);
        adminHttp.createContext("/shutdown", new ShutdownHandler());
        adminHttp.start();
    }
}
