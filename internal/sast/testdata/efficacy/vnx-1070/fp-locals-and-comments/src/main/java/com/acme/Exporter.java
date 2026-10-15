package com.acme;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.Serializable;

public class Exporter implements Serializable {
    // private Socket socket;  (removed: sockets are not serializable)
    private String target;

    public void export(byte[] data) throws java.io.IOException {
        try (OutputStream out = new FileOutputStream(target)) {
            out.write(data);
        }
        final Thread t = new Thread(() -> {});
        String note = "private Socket socket;";
    }
}
