package com.acme.net;

import java.io.IOException;
import java.io.InputStream;

public class Frame {
    public int fill(InputStream in) throws IOException {
        byte header[] = new byte[16];
~>        return in.read(header, 0, 16);
    }
}
