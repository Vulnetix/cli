package com.acme.net;

import java.net.InetSocketAddress;
import java.net.URI;

public class Endpoints {

    public InetSocketAddress admin(String host) {
~>        return new InetSocketAddress(host, 8443);
    }

    public URI adminUri(String host) {
        return URI.create("https://" + host + ":"
~>                + 8443 + "/admin");
    }

    public boolean isAdminPort(int port) {
~>        return port == 8443;
    }
}
