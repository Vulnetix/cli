package com.acme.files;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.*;

@RestController
public class StaticAssets {
    @GetMapping("/terms")
    public Resource terms() {
        return new FileSystemResource("/var/www/legal/terms.pdf");
    }

    @GetMapping("/logo/{size}")
    public Resource logo(@PathVariable String size) {
        return new ClassPathResource("static/logo-" + size + ".png");
    }

    @GetMapping("/version")
    public byte[] version() throws IOException {
        return Files.readAllBytes(Paths.get("/etc/acme/version"));
    }
}
