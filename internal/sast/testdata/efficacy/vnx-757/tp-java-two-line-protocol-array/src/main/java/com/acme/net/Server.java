package com.acme.net;

import javax.net.ssl.SSLServerSocket;

public class Server {
~>    private static final String[] PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.2"};

    void configure(SSLServerSocket socket) {
        socket.setEnabledProtocols(
~>            new String[] {"TLSv1.1", "TLSv1.2"});
        socket.setEnabledProtocols(PROTOCOLS);
    }
}
