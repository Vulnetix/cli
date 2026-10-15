package com.acme;

import java.io.InputStream;
import java.io.Serializable;
import java.net.Socket;

public class Session implements Serializable {
    private static final long serialVersionUID = 1L;

    private String user;
~>    private Socket socket;
~>    protected final InputStream in;

    public Session(Socket s) throws java.io.IOException {
        this.socket = s;
        this.in = s.getInputStream();
    }
}
