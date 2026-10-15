package com.acme.cli;

import java.nio.file.Files;
import java.nio.file.Path;

public class TokenStore {
    public void save(Path dir, String refreshToken) throws Exception {
~>        Files.writeString(dir.resolve("refresh_token"), refreshToken);
    }

    public void saveCredentials(Path credentialsFile, byte[] data) throws Exception {
~>        Files.write(credentialsFile, data);
    }
}
