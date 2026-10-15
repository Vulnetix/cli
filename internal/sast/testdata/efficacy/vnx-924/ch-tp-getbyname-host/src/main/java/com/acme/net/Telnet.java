package com.acme.net;

public class Telnet {
    Socket dial(String host) throws IOException {
~>        return new Socket(InetAddress.getByName(host),
                23);
    }
}
