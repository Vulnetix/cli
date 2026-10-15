package com.acme;

import java.io.InputStream;
import java.io.Serializable;
import java.net.Socket;

public class Session implements Serializable {
    private transient Socket socket;
    private final transient InputStream in;
    private String user;

    public Session(InputStream in) {
        this.in = in;
    }
}
