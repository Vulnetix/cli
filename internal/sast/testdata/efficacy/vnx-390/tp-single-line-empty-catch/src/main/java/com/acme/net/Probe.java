package com.acme.net;

import java.net.Socket;

public class Probe {
    public boolean reachable(String host, int port) {
        boolean ok = false;
        try (Socket s = new Socket(host, port)) {
            ok = true;
~>        } catch (Exception e) {}
        return ok;
    }

    public void close(Socket s) {
~>        try { s.close(); } catch (java.io.IOException | RuntimeException e) { }
    }
}
