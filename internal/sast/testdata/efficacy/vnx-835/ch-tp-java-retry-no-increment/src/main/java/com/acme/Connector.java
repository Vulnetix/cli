package com.acme;

import java.io.IOException;

public class Connector {
    private final Client client;
    private final int maxRetries;
    private boolean connected;

    public Connector(Client client, int maxRetries) {
        this.client = client;
        this.maxRetries = maxRetries;
    }

    public void open(String host) {
        int retries = 0;
~>        while (retries < maxRetries) {
            try {
                client.connect(host);
                connected = true;
            } catch (IOException e) {
                System.err.println("connect failed: " + e.getMessage());
            }
        }
    }
}
