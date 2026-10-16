package com.acme.io;

import java.io.IOException;
import java.io.InputStream;

final class Header {
    static int readHeader(InputStream in) throws IOException {
        byte[] header = new byte[512];
        return in.read(header, 0, header.length);
    }
}
