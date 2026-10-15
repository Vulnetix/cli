package com.example;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;

public class Upload {
    byte[] read(File uploadFile, Path p, ZipEntry entry) throws Exception {
~>        byte[] buf = new byte[(int) uploadFile.length()];
~>        int size = (int)Files.size(p);
~>        byte[] data = new byte[(int) entry.getSize()];
        return buf;
    }

    int seed(java.net.HttpURLConnection conn) {
~>        int len = (int) conn.getContentLengthLong();
~>        short id = (short) System.currentTimeMillis();
        return len + id;
    }
}
