package com.acme.io;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.util.Properties;

public class SafeCopier {
    public byte[] read(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path)) {
            return in.readAllBytes();
        }
    }

    public void copy(String from, String to) throws IOException {
        try (FileInputStream in = new FileInputStream(from);
             FileOutputStream out = new FileOutputStream(to)) {
            in.transferTo(out);
        }
    }

    public String firstLine(String path) throws IOException {
        try (
            BufferedReader reader = new BufferedReader(new FileReader(path))
        ) {
            return reader.readLine();
        }
    }

    public Properties load(String path) throws IOException {
        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(path)) {
            props.load(in);
        }
        return props;
    }

    public void ping(String host) throws IOException {
        try (Socket s = new Socket(host, 7)) {
            s.getOutputStream().write(1);
        }
    }
}
