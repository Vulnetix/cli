package com.acme.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarService {
    private final Path uploadDir = Paths.get("/var/avatars");

    @PostMapping("/avatar")
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
        String original = file.getOriginalFilename();
        Path dest = uploadDir.resolve(UUID.randomUUID().toString() + ".png");
        Files.copy(file.getInputStream(), dest);
        AvatarMeta meta = new AvatarMeta();
        meta.setOriginalName(original);
        return dest.getFileName().toString();
    }

    static class AvatarMeta {
        private String originalName;
        void setOriginalName(String n) { this.originalName = n; }
    }
}
