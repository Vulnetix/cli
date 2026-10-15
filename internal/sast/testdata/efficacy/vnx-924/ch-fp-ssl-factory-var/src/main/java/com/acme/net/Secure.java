package com.acme.net;

public class Secure {
    Socket dial(String host, int port) throws IOException {
        SocketFactory factory = SSLSocketFactory.getDefault();
        SSLSocket s = (SSLSocket) factory.createSocket(host, port);
        SSLServerSocket ss = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(8443);
        s.startHandshake();
        return s;
    }
}
