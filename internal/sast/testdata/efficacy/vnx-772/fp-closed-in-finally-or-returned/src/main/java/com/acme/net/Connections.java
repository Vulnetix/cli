package com.acme.net;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Connection;
import java.sql.DriverManager;

public class Connections {
    private Socket socket;

    public Socket open(String host, int port) throws IOException {
        Socket s = new Socket(host, port);
        s.setSoTimeout(5000);
        return s;
    }

    public void connect(String host) throws IOException {
        this.socket = new Socket(host, 80);
    }

    public int readOne(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        try {
            return in.read();
        } finally {
            in.close();
        }
    }

    public void serve(int port) throws IOException {
        ServerSocket server = new ServerSocket(port);
        while (true) {
            Socket client = server.accept();
            new Thread(new Handler(client)).start();
        }
    }

    public void quiet(String url) throws Exception {
        Connection conn = DriverManager.getConnection(url);
        try {
            conn.createStatement().execute("select 1");
        } finally {
            closeQuietly(conn);
        }
    }

    private static void closeQuietly(AutoCloseable c) {
        try { c.close(); } catch (Exception ignored) { }
    }
}
