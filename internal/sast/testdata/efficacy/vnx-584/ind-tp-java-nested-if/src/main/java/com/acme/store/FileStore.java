package com.acme.store;

import java.io.FileOutputStream;
import java.io.IOException;

public class FileStore {
    public boolean write(String path, byte[] data) throws IOException {
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(path);
            out.write(data);
            return true;
        } catch (IOException e) {
            throw new StoreException("write failed", e);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) {
~>                    return false;
                }
            }
        }
    }

    public int count() {
        try {
            return Index.count();
        } finally {
            Index.unlock();
~>            return -1;
        }
    }
}
