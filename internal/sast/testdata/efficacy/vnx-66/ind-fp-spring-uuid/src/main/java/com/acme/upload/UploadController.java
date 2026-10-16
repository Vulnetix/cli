package com.acme.upload;

import java.io.File;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class UploadController {

    private static final Logger log = LoggerFactory.getLogger(UploadController.class);
    private final File dir = new File("/srv/uploads");
    private final DocumentRepository documents;

    public UploadController(DocumentRepository documents) {
        this.documents = documents;
    }

    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
        String original = file.getOriginalFilename();
        log.info("received upload {}", original);
        file.transferTo(new File(dir, UUID.randomUUID().toString() + ".bin"));
        documents.save(new Document(original));
        return "stored";
    }
}
