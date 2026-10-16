package com.acme;

import java.io.IOException;
import java.net.Socket;
import javax.ejb.Stateless;

@Stateless
public class ClientBean {
    // new Thread(r).start(); in a comment
    private static final String NOTE = "new ServerSocket(80) and System.exit(1)";

    public void ping(String host) throws IOException {
        try (Socket s = new Socket(host, 7)) {
            s.getOutputStream().write(1);
        }
    }
}
