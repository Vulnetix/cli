package com.acme.upload;

import java.util.Set;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.multipart.MultipartFile;

public class UploadController {
    private static final Set<String> ALLOWED = Set.of("pdf", "png");

    public boolean accept(MultipartFile file) {
        String fileName = file.getOriginalFilename();
        String ext = FilenameUtils.getExtension(fileName).toLowerCase();
        String tail = fileName.substring(fileName.lastIndexOf('.') + 1);
        return ALLOWED.contains(ext) && fileName.toLowerCase().endsWith("." + tail.toLowerCase());
    }
}
