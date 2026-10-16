package com.acme.upload;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class UploadService {

    public byte[] readUpload(File uploadFile) throws IOException {
~>        byte[] buf = new byte[(int) uploadFile.length()];
        try (FileInputStream in = new FileInputStream(uploadFile)) {
            in.read(buf);
        }
        return buf;
    }

    public int quotaUsed(Path p) throws IOException {
~>        int size = (int) Files.size(p);
        return size;
    }
}
