package com.acme.io;

import java.io.IOException;
import java.io.InputStream;

public class Reader {
    private InputStream stream;

    public int read() throws IOException {
        try {
            return stream.read();
        } finally {
            stream.close();
~>            return -1;
        }
    }
}
