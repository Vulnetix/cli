package com.acme;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

public class TokenStore {
    public void save(Path tokenFile, String token) throws Exception {
        Files.createFile(tokenFile, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(tokenFile, token);
    }
}
