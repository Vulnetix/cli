package com.acme.store;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class BlockStore {
    public byte[] readBlock(File file, long offset) throws IOException {
~>        RandomAccessFile raf =
                new RandomAccessFile(file, "r");
        byte[] block = new byte[4096];
        raf.seek(offset);
        raf.readFully(block);
        return block;
    }
}
