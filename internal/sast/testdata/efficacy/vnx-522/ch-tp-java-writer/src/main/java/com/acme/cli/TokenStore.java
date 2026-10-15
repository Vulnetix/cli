package com.acme.cli;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class TokenStore {
    public void save(Path home, String accessToken) throws IOException {
~>        Files.writeString(home.resolve(".acme/token"), accessToken);
    }

    public void saveLegacy(String dir, String password) throws IOException {
~>        try (FileWriter w = new FileWriter(dir + "/credentials.properties")) {
            w.write("password=" + password);
        }
    }
}
