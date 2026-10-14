package com.acme.files;

import java.io.ByteArrayInputStream;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StaticController {
    @GetMapping("/terms")
    public ResponseEntity<Resource> terms(@RequestParam(defaultValue = "en") String lang) {
        return ResponseEntity.ok(new FileSystemResource("/srv/static/terms.pdf"));
    }

    @GetMapping("/logo")
    public ResponseEntity<Resource> logo() {
        return ResponseEntity.ok(new ClassPathResource("static/logo.png"));
    }

    @GetMapping("/csv")
    public ResponseEntity<InputStreamResource> csv(@RequestParam String sep) {
        byte[] data = ("a" + sep + "b").getBytes();
        return ResponseEntity.ok(new InputStreamResource(new ByteArrayInputStream(data)));
    }
}
