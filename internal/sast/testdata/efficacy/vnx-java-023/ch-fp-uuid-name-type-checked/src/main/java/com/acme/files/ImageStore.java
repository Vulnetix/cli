package com.acme.files;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class ImageStore {
    private static final Set<String> IMAGE_TYPES = Set.of("image/png", "image/jpeg");
    private final Path root;

    public ImageStore(Path root) {
        this.root = root;
    }

    public Path save(MultipartFile upload) throws IOException {
        String type = upload.getContentType();
        if (type == null || !IMAGE_TYPES.contains(type)) {
            throw new IllegalArgumentException("unsupported");
        }
        Path target = root.resolve(UUID.randomUUID() + ".img");
        Files.copy(upload.getInputStream(), target);
        return target;
    }
}
