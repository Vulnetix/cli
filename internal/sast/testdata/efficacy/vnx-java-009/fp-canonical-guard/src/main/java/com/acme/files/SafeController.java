package com.acme.files;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.*;

@RestController
public class SafeController {
    private final Path root = Paths.get("/srv/files").toAbsolutePath().normalize();
    private static final String BASE = "/srv/files";

    @GetMapping("/a")
    public byte[] a(@RequestParam String name) throws Exception {
        Path target = root.resolve(name).normalize();
        if (!target.startsWith(root)) {
            throw new SecurityException("outside root");
        }
        return Files.readAllBytes(target);
    }

    @GetMapping("/b")
    public String b(@RequestParam String doc) throws Exception {
        File f = new File(BASE, doc);
        if (!f.getCanonicalPath().startsWith(BASE + File.separator)) {
            throw new SecurityException("outside base");
        }
        return f.getName();
    }

    @GetMapping("/c")
    public String c(@RequestParam String report) throws Exception {
        if (report.contains("..") || !report.matches("[A-Za-z0-9_-]+")) {
            throw new IllegalArgumentException("bad name");
        }
        return new File(BASE, report).getPath();
    }
}
