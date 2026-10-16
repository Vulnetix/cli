package com.acme;

import org.springframework.web.multipart.MultipartFile;

public class UploadCtl {
    byte[] buffer(MultipartFile upload) {
~>        return new byte[(int) upload.getSize()];
    }
}
