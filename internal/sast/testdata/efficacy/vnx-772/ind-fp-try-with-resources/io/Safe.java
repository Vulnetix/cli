package io;

import java.io.*;
import java.net.Socket;
import java.sql.*;
import java.nio.file.*;

public class Safe {
    public byte[] a(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) {
            return in.readAllBytes();
        }
    }

    public void b(String host, int port, javax.sql.DataSource ds) throws Exception {
        try (Socket s = new Socket(host, port);
             Connection c = ds.getConnection()) {
            c.createStatement().execute("select 1");
        }
    }

    public long c(String p) throws IOException {
        try (var lines = Files.lines(Paths.get(p))) {
            return lines.count();
        }
    }
}
