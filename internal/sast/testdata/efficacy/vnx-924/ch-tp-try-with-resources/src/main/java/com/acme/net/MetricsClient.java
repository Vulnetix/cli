package com.acme.net;

import java.net.Socket;

public class MetricsClient {
    public void push(Config config, byte[] payload) throws IOException {
~>        try (Socket socket = new Socket(config.getHost(), config.getPort());
             OutputStream out = socket.getOutputStream()) {
            out.write(payload);
        }
    }
}
