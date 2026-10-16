package com.acme.ops;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class SecureAdmin {
    void start(int adminPort, int apiPort) throws Exception {
        SSLServerSocketFactory f = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket adminSocket = (SSLServerSocket) f.createServerSocket(adminPort);
        HttpsServer adminHttps = HttpsServer.create(new InetSocketAddress(adminPort + 1), 0);
        ServerSocket localAdmin = new ServerSocket(adminPort + 2, 50, InetAddress.getLoopbackAddress());
        ServerSocket publicApi = new ServerSocket(apiPort);
        HttpServer apiServer = HttpServer.create(new InetSocketAddress(apiPort + 1), 0);
    }
}
