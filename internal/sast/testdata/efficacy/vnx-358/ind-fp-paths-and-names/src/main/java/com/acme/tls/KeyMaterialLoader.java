package com.acme.tls;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

public class KeyMaterialLoader {
    public List<Path> certificateFiles(Path dir) throws IOException {
        try (var files = Files.list(dir)) {
            return files
                .filter(p -> p.getFileName().toString().endsWith(".pem"))
                .filter(p -> !p.getFileName().toString().startsWith("."))
                .collect(Collectors.toList());
        }
    }

    public boolean isProdProfile(String profileName) {
        return profileName.contains("prod");
    }
}
