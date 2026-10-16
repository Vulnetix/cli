package com.acme.net;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.ZipEntry;

public class Fetcher {

    public byte[] fetch(URL url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
~>        int len = (int) conn.getContentLengthLong();
        byte[] body = new byte[len];
        conn.getInputStream().read(body);
        return body;
    }

    public short nextSequence() {
~>        short id = (short) System.currentTimeMillis();
        return id;
    }

    public byte[] entryBuffer(ZipEntry entry) {
~>        return new byte[(int) entry.getSize()];
    }
}
