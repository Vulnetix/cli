package com.acme;

import java.io.*;
import org.apache.commons.io.IOUtils;

public class Legacy {
    private InputStream source;

    public void open(File f) throws IOException {
        this.source = new FileInputStream(f);
    }

    public byte[] read(File f) throws IOException {
        FileInputStream in = null;
        try {
            in = new FileInputStream(f);
            return in.readAllBytes();
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    public String quiet(File f) throws IOException {
        InputStream in = new FileInputStream(f);
        try {
            return new String(in.readAllBytes());
        } finally {
            IOUtils.closeQuietly(in);
        }
    }

    public BufferedReader reader(File f) throws IOException {
        FileReader fr = new FileReader(f);
        return new BufferedReader(fr);
    }

    public InputStream stream(File f) throws IOException {
        FileInputStream in = new FileInputStream(f);
        return in;
    }
}
