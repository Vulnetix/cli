package com.acme.upload;

import java.io.File;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class SafeUpload {
    private final String dir = "/srv/uploads";

    public String upload(MultipartFile file) throws Exception {
        String ext = extension(file.getOriginalFilename());
        file.transferTo(new File(dir, UUID.randomUUID() + ext));
        log.info("uploaded {}", file.getOriginalFilename());
        return file.getOriginalFilename();
    }
}
