package com.acme.io;

import java.io.File;
import java.io.IOException;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;

public class Uploads {
    byte[] slurp(File uploadFile) {
~>        byte[] buf = new byte[(int) uploadFile.length()];
        return buf;
    }

    int sizeOf(Path p) throws IOException {
~>        int size = (int) Files.size(p);
        return size;
    }

    int remote(URLConnection conn) {
~>        int len = (int) conn.getContentLengthLong();
        return len;
    }

    short tag() {
~>        short id = (short) System.currentTimeMillis();
        return id;
    }
}
