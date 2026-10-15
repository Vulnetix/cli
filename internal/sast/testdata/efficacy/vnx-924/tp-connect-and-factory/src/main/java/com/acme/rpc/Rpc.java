package com.acme.rpc;

import java.net.InetSocketAddress;
import java.net.Socket;
import javax.net.SocketFactory;

public class Rpc {
    Socket open(String host) throws Exception {
        Socket s = new Socket();
~>        s.connect(new InetSocketAddress(host, 7001), 3000);
~>        Socket t = SocketFactory.getDefault().createSocket(host, 7002);
~>        java.net.Socket u = new java.net.Socket(
            "payments.internal.example.com", 7003);
        return s;
    }
}
