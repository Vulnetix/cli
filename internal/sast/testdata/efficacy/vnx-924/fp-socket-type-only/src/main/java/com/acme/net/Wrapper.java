package com.acme.net;

import java.net.Socket;

public class Wrapper {
    private final Socket socket;

    Wrapper(Socket socket) {
        this.socket = socket;
    }

    String describe() {
        return "Socket(" + socket.getInetAddress() + ")";
    }
}
