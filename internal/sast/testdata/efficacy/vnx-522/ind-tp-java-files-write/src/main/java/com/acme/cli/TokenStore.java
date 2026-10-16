package com.acme.cli;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class TokenStore {

    private final Path tokenPath = Paths.get(System.getProperty("user.home"), ".acme", "token");

    public void save(String accessToken) throws IOException {
        Files.createDirectories(tokenPath.getParent());
~>        Files.writeString(tokenPath, accessToken, StandardCharsets.UTF_8);
    }

    public void saveCredentials(String user, String password) throws IOException {
        String credentialsFile = System.getProperty("user.home") + "/.acme/credentials";
~>        try (FileWriter writer = new FileWriter(credentialsFile)) {
            writer.write(user + ":" + password);
        }
    }
}
