package com.acme.web;

import java.nio.file.Path;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class TermsController {

    @GetMapping("/terms")
    public Resource terms(@RequestParam(defaultValue = "en") String lang) {
        if ("de".equals(lang)) {
            return new FileSystemResource("/srv/legal/terms-de.pdf");
        }
        return new FileSystemResource("/srv/legal/terms-en.pdf");
    }

    @GetMapping("/logo")
    public Resource logo(@RequestParam String variant) {
        return new ClassPathResource("static/logo-" + variant + ".svg");
    }
}

@Service
class StorageService {
    private final Path dir;

    StorageService(Path dir) {
        this.dir = dir;
    }

    public Resource load(String name) {
        return new FileSystemResource(dir.resolve(name));
    }
}
