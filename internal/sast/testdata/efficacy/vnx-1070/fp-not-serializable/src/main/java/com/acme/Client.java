package com.acme;

import java.net.Socket;
import java.sql.Connection;

public class Client implements AutoCloseable {
    private Socket socket;
    private Connection connection;

    public void close() throws Exception {
        socket.close();
        connection.close();
    }
}
