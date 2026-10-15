package com.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;

public class Loader {
    public String first(String file) throws IOException {
        try (BufferedReader r = new BufferedReader(new FileReader(file))) {
            return r.readLine();
        }
    }

    public void ping(String url) throws Exception {
        try (Connection conn = DriverManager.getConnection(url);
             var st = conn.createStatement()) {
            st.execute("SELECT 1");
        }
    }
}
