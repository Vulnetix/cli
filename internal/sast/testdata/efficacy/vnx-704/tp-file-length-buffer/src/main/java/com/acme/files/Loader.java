package com.acme.files;

import java.io.File;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;

public class Loader {
    public byte[] read(File file) throws Exception {
~>        byte[] buf = new byte[(int) file.length()];
        try (FileInputStream in = new FileInputStream(file)) {
            in.read(buf);
        }
        return buf;
    }

    public byte[] readPath(Path p) throws Exception {
~>        byte[] out = new byte[(int)Files.size(p)];
        return out;
    }

    public int tail(RandomAccessFile raf) throws Exception {
~>        int pos = (int) raf.getFilePointer();
~>        return (int) new File("/var/log/app.log").length() - pos;
    }
}
