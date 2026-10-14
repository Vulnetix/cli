package com.example.upload;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class AvatarController {
    private final String uploadDir = "/var/www/uploads";

    @PostMapping("/avatar")
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
~>        file.transferTo(new File(uploadDir, file.getOriginalFilename()));
        return "ok";
    }

    @PostMapping("/doc")
    public String doc(@RequestParam("file") MultipartFile upload) throws IOException {
        String name = upload.getOriginalFilename();
        Path target = Paths.get(uploadDir).resolve(name);
        try (InputStream in = upload.getInputStream()) {
~>            Files.copy(in, target);
        }
        return name;
    }

    @PostMapping("/raw")
    public void raw(@RequestParam("file") MultipartFile f) throws IOException {
~>        Files.write(Paths.get(uploadDir,
                f.getOriginalFilename()), f.getBytes());
    }
}
