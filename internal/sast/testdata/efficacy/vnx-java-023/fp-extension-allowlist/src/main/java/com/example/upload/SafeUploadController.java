package com.example.upload;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class SafeUploadController {
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("png", "jpg", "gif");
    private final Path root = Paths.get("/srv/uploads");

    @PostMapping("/image")
    public String image(@RequestParam("file") MultipartFile file) throws IOException {
        String name = file.getOriginalFilename();
        String ext = FilenameUtils.getExtension(name).toLowerCase();
        if (!ALLOWED_EXTENSIONS.contains(ext)) {
            throw new IllegalArgumentException("type not allowed");
        }
        file.transferTo(root.resolve(name));
        return name;
    }

    @PostMapping("/zip")
    public String zip(@RequestParam("file") MultipartFile file) throws IOException {
        if (!file.getOriginalFilename().toLowerCase().endsWith(".zip")) {
            return "only zip";
        }
        Files.copy(file.getInputStream(), root.resolve(file.getOriginalFilename()));
        return "ok";
    }
}
