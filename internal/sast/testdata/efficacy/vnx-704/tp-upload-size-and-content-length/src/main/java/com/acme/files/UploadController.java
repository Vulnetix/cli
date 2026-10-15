package com.acme.files;

import java.net.HttpURLConnection;
import java.util.zip.ZipEntry;
import org.springframework.web.multipart.MultipartFile;

public class UploadController {
    public byte[] accept(MultipartFile upload) {
~>        return new byte[(int) upload.getSize()];
    }

    public byte[] download(HttpURLConnection conn) {
~>        int len = (int) conn.getContentLengthLong();
        return new byte[len];
    }

    public byte[] entry(ZipEntry e) {
~>        byte[] data = new byte[(int) e.getSize()];
~>        int packed = (int) e.getCompressedSize();
        return data;
    }
}
