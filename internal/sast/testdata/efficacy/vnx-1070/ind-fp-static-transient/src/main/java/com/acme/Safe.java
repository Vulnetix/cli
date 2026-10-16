package com.acme;
import java.io.Serializable;
import java.net.Socket;
import java.sql.Connection;
import java.util.logging.Logger;
public class Safe implements Serializable {
    private static final Logger LOG = Logger.getLogger("s");
    private static Socket shared;
    private transient Connection connection;
    private transient volatile Thread worker;
    private final String host;
    private final int port;
    public Safe(String h, int p) { host = h; port = p; }
    void f() {
        Socket local = new Socket();
        Thread t = new Thread(() -> {});
    }
}
