package com.acme.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class Loader {

    public byte[] load(File f) throws IOException {
~>        byte[] data = new byte[(int) f.length()];
        try (FileInputStream in = new FileInputStream(f)) {
            in.read(data);
        }
        return data;
    }
}
