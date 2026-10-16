package com.acme;
public class Tls {
    void f(String host) throws Exception {
        SSLSocket s = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, 443);
        SSLServerSocket ss = (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket(8443);
        Socket plain = null;
        Socket up = factory.createSocket(plain, host, 993, true);
    }
}
