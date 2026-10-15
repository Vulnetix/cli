package com.acme;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Set;

public class AdminListener {
    private static final Set<String> ALLOWED = Set.of("ops1.example.com", "ops2.example.com");

    boolean permitted(Socket socket) {
~>        String peer = ((InetSocketAddress) socket.getRemoteSocketAddress()).getHostName();
        return ALLOWED.contains(peer);
    }
}
