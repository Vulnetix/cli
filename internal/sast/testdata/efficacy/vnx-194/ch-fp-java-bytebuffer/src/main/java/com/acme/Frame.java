package com.acme;

import java.nio.ByteBuffer;

public class Frame {
    static int length(byte[] hdr) {
        int flags = 1 << 8;
        return Short.toUnsignedInt(ByteBuffer.wrap(hdr).getShort()) | flags;
    }
}
