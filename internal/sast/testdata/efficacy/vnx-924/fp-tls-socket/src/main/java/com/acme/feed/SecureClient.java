package com.acme.feed;

import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SecureClient {
    public void send(String host) throws Exception {
        SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket s = (SSLSocket) f.createSocket(host, 443);
        s.startHandshake();
        var server = SSLServerSocketFactory.getDefault().createServerSocket(8443);
    }
}
