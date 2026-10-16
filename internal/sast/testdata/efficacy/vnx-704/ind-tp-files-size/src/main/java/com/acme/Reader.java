package com.acme;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Reader {
    byte[] read(Path p) throws IOException {
~>        byte[] out = new byte[(int) Files.size(p)];
        return out;
    }
}
