package com.acme.proto;

import java.nio.ByteBuffer;

public class FrameReader {

    public boolean isFrame(ByteBuffer b) {
~>        return b.getInt(0) == 0xCAFEBABE;
    }

    public boolean isTrailer(int word) {
~>        return word == 0xCAFEBABE || word == 0;
    }

    public void writeHeader(ByteBuffer out) {
~>        out.putInt(0xCAFEBABE);
~>        out.putLong(86400000L);
    }

    public boolean expired(long ageMillis) {
~>        return ageMillis > 86400000L;
    }

    public long nextRefresh(long now) {
~>        return now + 86400000L;
    }
}
