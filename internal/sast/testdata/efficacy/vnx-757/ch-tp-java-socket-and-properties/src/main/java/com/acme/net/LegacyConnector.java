package com.acme.net;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class LegacyConnector {
    public SSLSocket open(String host, int port) throws Exception {
~>        SSLContext ctx = SSLContext.getInstance("TLSv1.1");
        ctx.init(null, null, null);
        SSLSocketFactory factory = ctx.getSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
~>        socket.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"});
        return socket;
    }

    static {
~>        System.setProperty("https.protocols", "TLSv1,TLSv1.1,TLSv1.2");
    }
}
