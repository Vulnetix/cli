package com.acme;
import org.springframework.web.multipart.MultipartFile;
import java.nio.file.*;
import java.util.*;
public class SafeUpload {
    private static final Set<String> OK = Set.of("png", "jpg", "pdf");
    void save(MultipartFile f) throws Exception {
        String ext = org.apache.commons.io.FilenameUtils.getExtension(f.getOriginalFilename()).toLowerCase();
        if (!OK.contains(ext) || !f.getContentType().startsWith("image/")) {
            throw new IllegalArgumentException("bad type");
        }
        Path dest = Paths.get("/data/store", UUID.randomUUID() + "." + ext);
        Files.copy(f.getInputStream(), dest);
    }
}
