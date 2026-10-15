package com.acme.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class DocService {
    private final Path dir;
    private final DocRepository repo;

    public DocService(Path dir, DocRepository repo) {
        this.dir = dir;
        this.repo = repo;
    }

    public Doc save(MultipartFile file) throws IOException {
        Doc doc = new Doc();
        doc.setOriginalName(file.getOriginalFilename());
        String stored = UUID.randomUUID().toString();
        Files.copy(file.getInputStream(), dir.resolve(stored));
        doc.setStoredName(stored);
        return repo.save(doc);
    }
}
