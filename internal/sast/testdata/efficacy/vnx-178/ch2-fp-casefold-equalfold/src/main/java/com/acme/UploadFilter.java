package com.acme;

import org.springframework.web.multipart.MultipartFile;

public class UploadFilter {
    public boolean blocked(MultipartFile file) {
        String name = file.getOriginalFilename();
        return name != null && name.toLowerCase(java.util.Locale.ROOT).endsWith(".jsp");
    }
}
