package com.acme.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class Copier {
    public static long copy(InputStream in, OutputStream out) throws IOException {
        byte[] chunk = new byte[4096];
        long total = 0;
        int n;
~>        while ((n = in.read(chunk, 0, 4096)) != -1) {
            out.write(chunk, 0, n);
            total += n;
        }
        return total;
    }
}
