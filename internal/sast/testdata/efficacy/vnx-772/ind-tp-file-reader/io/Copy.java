package io;

import java.io.*;

public class Copy {
    public void copy(File src, File dst) throws IOException {
~>        FileInputStream in = new FileInputStream(src);
~>        FileOutputStream out = new FileOutputStream(dst);
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
    }
}
