package com.acme.upload;

import java.io.File;
import org.springframework.web.multipart.MultipartFile;

public class Audit {
    void record(File destinationDir, MultipartFile multipartFile) {
        log.debug("File saved to {}", new File(destinationDir, multipartFile.getOriginalFilename()));
    }
}
