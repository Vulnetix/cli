package com.example;

import org.springframework.web.multipart.MultipartFile;

public class Check {
    boolean blocked(MultipartFile file) {
        String name = file.getOriginalFilename();
        if (name.toLowerCase().endsWith(".jsp")) {
            return true;
        }
        String ext = name.substring(name.lastIndexOf('.') + 1);
        return "exe".equalsIgnoreCase(ext);
    }
}
