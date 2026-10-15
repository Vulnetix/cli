package com.acme.upload;

import java.io.File;
import java.io.IOException;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class AttachmentService {
    private final File dir = new File("/srv/attachments");
    private final AttachmentRepository repo;

    public AttachmentService(AttachmentRepository repo) {
        this.repo = repo;
    }

    public void save(MultipartFile upload) throws IOException {
        String original = upload.getOriginalFilename();
        String storedName = UUID.randomUUID().toString();
        upload.transferTo(new File(dir, storedName));
        repo.save(new Attachment(storedName, original));
    }
}
