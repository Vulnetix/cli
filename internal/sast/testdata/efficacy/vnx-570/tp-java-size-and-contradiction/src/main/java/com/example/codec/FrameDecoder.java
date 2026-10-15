package com.example.codec;

import java.util.List;

public class FrameDecoder {
    static final int TYPE_DATA = 0;
    static final int TYPE_PING = 9;

    public int decode(byte[] frame, List<String> errors, String header) {
~>        if (frame.length < 0) {
            throw new IllegalArgumentException("empty frame");
        }
~>        if (errors.size() < 0 || header.length() < 0) {
            return -1;
        }
        int type = frame[0];
~>        if (type == TYPE_DATA && type == TYPE_PING) {
            return 2;
        }
~>        if (type == 1 && type == 3) {
            return 3;
        }
        return type;
    }
}
