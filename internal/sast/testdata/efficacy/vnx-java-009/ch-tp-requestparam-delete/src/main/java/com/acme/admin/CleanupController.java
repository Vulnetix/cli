package com.acme.admin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CleanupController {

    @DeleteMapping("/admin/exports")
    public String remove(@RequestParam("file") String exportFile) throws IOException {
~>        Path location = Path.of("/data/exports", exportFile);
        Files.deleteIfExists(location);
        return "deleted";
    }
}
