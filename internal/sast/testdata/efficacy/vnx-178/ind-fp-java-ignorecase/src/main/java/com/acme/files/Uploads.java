package com.acme.files;

import org.springframework.web.multipart.MultipartFile;

public class Uploads {

    public static boolean rejected(MultipartFile file) {
        String name = file.getOriginalFilename();
        String ext = name.substring(name.lastIndexOf('.') + 1);
        return ext.equalsIgnoreCase("jsp") || ext.equalsIgnoreCase("war");
    }

    public static boolean isAdmin(String role) {
        return role.equals("admin");
    }
}
