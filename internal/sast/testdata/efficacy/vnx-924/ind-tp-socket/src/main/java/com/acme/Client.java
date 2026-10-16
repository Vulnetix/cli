package com.acme;
public class Client {
    void send(String host, int port) throws Exception {
~>        try (Socket s = new Socket(host, port)) {
            s.getOutputStream().write(payload);
        }
    }
}
