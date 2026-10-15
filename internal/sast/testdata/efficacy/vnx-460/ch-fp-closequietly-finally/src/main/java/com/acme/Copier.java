package com.acme;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class Copier {
    public void copy(String src, OutputStream out) throws Exception {
        InputStream in = null;
        try {
            in = new FileInputStream(src);
            in.transferTo(out);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
}
