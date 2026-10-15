package com.acme.web;

import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Secured("ROLE_ADMIN")
public class AdminFilesController {
    private final Path logs = Paths.get("/var/log/acme");

    @GetMapping("/admin/logs/{name}")
    public Resource log(@PathVariable String name) {
        return new FileSystemResource(logs.resolve(name));
    }
}
