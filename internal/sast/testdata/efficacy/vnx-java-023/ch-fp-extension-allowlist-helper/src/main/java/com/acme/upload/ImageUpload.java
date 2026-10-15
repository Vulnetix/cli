package com.acme.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import org.springframework.web.multipart.MultipartFile;

public class ImageUpload {
    private static final Set<String> PERMITTED = Set.of("png", "jpg", "gif");
    private final Path root;

    public ImageUpload(Path root) {
        this.root = root;
    }

    public void store(MultipartFile image) throws IOException {
        String name = image.getOriginalFilename();
        String ext = name.substring(name.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT);
        if (!PERMITTED.contains(ext)) {
            throw new IllegalArgumentException("unsupported type");
        }
        Files.copy(image.getInputStream(), root.resolve(name));
    }
}
