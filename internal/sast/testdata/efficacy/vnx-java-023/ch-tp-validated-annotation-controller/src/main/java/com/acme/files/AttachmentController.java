package com.acme.files;

import java.io.File;
import java.io.IOException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@Validated
@RestController
public class AttachmentController {
    private final String uploadRoot = "/var/www/acme/static/attachments";

    @PostMapping("/attachments")
    public String store(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return "empty";
        }
~>        file.transferTo(new File(uploadRoot + File.separator + file.getOriginalFilename()));
        return "ok";
    }
}
