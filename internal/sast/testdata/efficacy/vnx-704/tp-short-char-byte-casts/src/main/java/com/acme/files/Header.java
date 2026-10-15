package com.acme.files;

import java.io.File;

public class Header {
    public void write(java.nio.ByteBuffer b, File f) {
~>        b.putShort((short) f.length());
~>        b.put((byte) f.length());
    }
}
