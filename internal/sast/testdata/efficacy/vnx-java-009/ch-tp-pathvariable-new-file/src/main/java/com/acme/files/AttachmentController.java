package com.acme.files;

import java.io.File;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AttachmentController {
    private final File baseDir = new File("/srv/attachments");

    @GetMapping("/attachments/{name}")
    public ResponseEntity<Resource> download(@PathVariable("name") String name) {
~>        File target = new File(baseDir, name);
        if (!target.exists()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(new FileSystemResource(target));
    }
}
