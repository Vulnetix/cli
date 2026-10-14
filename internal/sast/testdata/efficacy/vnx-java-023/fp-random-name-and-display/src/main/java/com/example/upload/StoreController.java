package com.example.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class StoreController {
    private static final Logger log = LoggerFactory.getLogger(StoreController.class);
    private final Path root = Paths.get("/srv/blobs");

    @PostMapping("/blob")
    public String blob(@RequestParam("file") MultipartFile file) throws IOException {
        String display = file.getOriginalFilename();
        log.info("received {}", display);
        Path target = root.resolve(UUID.randomUUID().toString());
        Files.copy(file.getInputStream(), target);
        metadata.save(target.toString(), display);
        return target.getFileName().toString();
    }

    private final Meta metadata = new Meta();

    static class Meta { void save(String a, String b) {} }
}
