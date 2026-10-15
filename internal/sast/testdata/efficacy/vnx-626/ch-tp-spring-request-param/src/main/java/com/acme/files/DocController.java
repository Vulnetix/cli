package com.acme.files;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.*;

@RestController
public class DocController {
    private static final String BASE = "/srv/docs";

    @GetMapping("/doc")
    public byte[] doc(@RequestParam("name") String name) throws Exception {
~>        Path p = Paths.get(BASE, name + ".md");
        return Files.readAllBytes(p);
    }

    @GetMapping("/img/{id}")
    public byte[] img(@PathVariable String id) throws Exception {
~>        return Files.readAllBytes(new File(BASE, id + ".png").toPath());
    }
}
