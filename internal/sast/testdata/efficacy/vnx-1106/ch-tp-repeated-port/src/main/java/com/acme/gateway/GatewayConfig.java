package com.acme.gateway;

import java.net.InetSocketAddress;

public class GatewayConfig {

    public InetSocketAddress publicAddress(String host) {
~>        return new InetSocketAddress(host, 8443);
    }

    public String publicUrl(String host) {
~>        return "https://" + host + ":" + 8443 + "/";
    }

    public boolean isPublicPort(int port) {
~>        return port == 8443;
    }
}
