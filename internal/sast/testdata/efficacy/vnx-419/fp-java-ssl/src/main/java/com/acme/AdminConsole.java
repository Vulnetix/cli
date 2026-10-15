package com.acme;

import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class AdminConsole {
    public void start() throws Exception {
        SSLServerSocketFactory f = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket adminSocket = (SSLServerSocket) f.createServerSocket(adminPort);
        ServerSocket localAdmin = new ServerSocket(adminPort, 50, InetAddress.getLoopbackAddress());
        ServerSocket data = new ServerSocket(8080);
        HttpsServer adminHttps = HttpsServer.create(new InetSocketAddress(adminPort), 0);
    }
}
