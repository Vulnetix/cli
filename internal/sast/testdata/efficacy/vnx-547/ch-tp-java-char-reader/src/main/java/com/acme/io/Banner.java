package com.acme.io;

import java.io.IOException;
import java.io.Reader;

public class Banner {
    public String read(Reader reader) throws IOException {
        char[] cbuf = new char[1024];
~>        int n = reader.read(cbuf, 0, 1024);
        return new String(cbuf, 0, Math.max(n, 0));
    }
}
