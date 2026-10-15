package com.acme.web;

import org.springframework.web.multipart.MultipartFile;

public class UploadController {

    public int store(MultipartFile file) {
~>        int bytes = (int)file.getSize();
        return bytes;
    }
}
