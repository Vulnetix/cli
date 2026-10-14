package com.acme.api;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
public class BodyController {
    @PostMapping("/notes")
    public void save(@RequestBody String body, HttpServletRequest request) throws Exception {
        Path out = Paths.get("/srv/notes", "latest.txt");
        Files.write(out, body.getBytes());
        java.io.InputStream in = request.getInputStream();
        Files.copy(in, Paths.get("/srv/notes", "upload.bin"));
    }
}
