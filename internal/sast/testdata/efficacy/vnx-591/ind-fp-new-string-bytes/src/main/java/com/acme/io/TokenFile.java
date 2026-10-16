package com.acme.io;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public final class TokenFile {

    public static String readHeader(Path path) throws IOException {
        byte[] raw = Files.readAllBytes(path);
        String decoded = new String(Base64.getDecoder().decode(raw), StandardCharsets.UTF_8);
        return decoded.split("\n", 2)[0];
    }

    public static String readPrefix(Reader reader) throws IOException {
        char[] buffer = new char[64];
        int n = reader.read(buffer);
        return new String(buffer, 0, Math.max(n, 0));
    }

    public static String label(char[] name) {
        return String.valueOf(name);
    }
}
