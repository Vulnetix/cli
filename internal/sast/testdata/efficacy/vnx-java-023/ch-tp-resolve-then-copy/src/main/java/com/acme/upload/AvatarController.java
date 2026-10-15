package com.acme.upload;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private final Path uploadDir = Paths.get("/srv/acme/avatars");

    @PostMapping("/avatar")
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
        String filename = file.getOriginalFilename();
        Path dest = uploadDir.resolve(filename);
~>        Files.copy(file.getInputStream(), dest, StandardCopyOption.REPLACE_EXISTING);
        return "/avatars/" + filename;
    }

    @PostMapping("/doc")
    public void doc(@RequestParam("doc") MultipartFile doc) throws IOException {
~>        Files.write(Paths.get("/srv/acme/docs", doc.getOriginalFilename()), doc.getBytes());
    }
}
