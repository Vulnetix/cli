package com.acme;

import java.nio.file.*;
import java.io.IOException;
import org.springframework.web.bind.annotation.*;

@RestController
public class DocController {
    private final String root = "/srv/docs/";

    @GetMapping("/docs")
    public byte[] read(@RequestParam("path") String path) throws IOException {
~>        Path p = Paths.get(root + path);
        return Files.readAllBytes(p);
    }
}
