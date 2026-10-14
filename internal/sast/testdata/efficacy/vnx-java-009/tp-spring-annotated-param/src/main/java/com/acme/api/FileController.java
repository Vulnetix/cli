package com.acme.api;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.core.io.FileSystemResource;
import org.springframework.web.bind.annotation.*;

@RestController
public class FileController {
    private final Path root = Paths.get("/srv/files");

    @GetMapping("/files/{name}")
    public byte[] read(@PathVariable("name") String name) throws Exception {
~>        Path target = root.resolve(name);
        return Files.readAllBytes(target);
    }

    @GetMapping("/raw")
    public FileSystemResource raw(@RequestParam(value = "path", required = false) final String path) {
~>        return new FileSystemResource("/srv/files/" + path);
    }

    @DeleteMapping("/files")
    public void delete(@RequestHeader("X-File") String file) throws Exception {
~>        Files.deleteIfExists(Path.of("/srv/files", file));
    }
}
