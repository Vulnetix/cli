package com.acme;

import java.net.HttpURLConnection;
import java.nio.file.Files;
import java.nio.file.Path;

public class Upload {
    byte[] read(Path path, HttpURLConnection conn) throws Exception {
~>        int size = (int) Files.size(path);
~>        int declared = (int) conn.getContentLengthLong();
        return new byte[Math.max(size, declared)];
    }
}
