package com.acme.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

public class SecureTokenStore {

    private final Path tokenPath = Paths.get(System.getProperty("user.home"), ".acme", "token");

    public void save(String accessToken) throws IOException {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        if (!Files.exists(tokenPath)) {
            Files.createFile(tokenPath, PosixFilePermissions.asFileAttribute(ownerOnly));
        }
        Files.writeString(tokenPath, accessToken, StandardCharsets.UTF_8);
    }
}
