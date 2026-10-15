package com.acme.img;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class Jpeg {
    boolean paddedHeader(DataInputStream in, ByteBuffer buf) throws IOException {
        if (in.read() == 0 && in.read() == 0) {
            return true;
        }
        return buf.get() == 0 && buf.get() == 0;
    }

    boolean twoTokens(java.util.Iterator<String> it) {
        return it.hasNext() && it.next().isEmpty() && it.hasNext() && it.next().isEmpty();
    }
}
