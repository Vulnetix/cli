package com.acme;

import java.io.*;
import java.sql.*;

public class ConfigLoader {
    public String firstLine(String path) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            return reader.readLine();
        }
    }

    public int count(String url) throws SQLException {
        try (Connection conn = DriverManager.getConnection(url);
             Statement st = conn.createStatement()) {
            return st.executeUpdate("DELETE FROM tmp");
        }
    }

    public void copy(File a, File b) throws IOException {
        try (
            FileInputStream in = new FileInputStream(a);
            FileOutputStream out = new FileOutputStream(b)
        ) {
            in.transferTo(out);
        }
    }
}
