package com.acme.upload;

public class UploadController {
    public String upload(MultipartFile file) {
        String fileName = file.getOriginalFilename();
~>        String ext = fileName.substring(fileName.indexOf(".") + 1);
~>        if (!file.getOriginalFilename().contains(".pdf")) {
            return "rejected";
        }
~>        String type = fileName.split("\\.")[1];
        return store(file, ext, type);
    }
}
