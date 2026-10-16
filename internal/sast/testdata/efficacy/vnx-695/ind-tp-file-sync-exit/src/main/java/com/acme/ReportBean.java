package com.acme;

import java.io.FileOutputStream;
import java.io.IOException;
import jakarta.ejb.Singleton;

@Singleton
public class ReportBean {
    private int counter;

    public void write(byte[] data) throws IOException {
~>        try (FileOutputStream out = new FileOutputStream("/var/reports/out.bin")) {
            out.write(data);
        }
    }

~>    public synchronized void bump() {
        counter++;
    }

    public void stop() {
~>        System.exit(1);
    }
}
