package com.acme;

import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class AdminEndpoint {
    public ServerSocket open(int adminPort) throws Exception {
        SSLServerSocketFactory f = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        ServerSocket adminTls = f.createServerSocket(adminPort);
        ServerSocket adminLocal = new ServerSocket(adminPort + 1, 50, InetAddress.getLoopbackAddress());
        adminLocal.close();
        return adminTls;
    }
}
