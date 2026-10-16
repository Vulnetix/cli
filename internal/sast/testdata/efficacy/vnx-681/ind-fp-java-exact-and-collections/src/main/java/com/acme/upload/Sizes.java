package com.acme.upload;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class Sizes {

    public byte[] readUpload(File uploadFile) {
        return new byte[Math.toIntExact(uploadFile.length())];
    }

    public long quotaUsed(Path p) throws IOException {
        long size = Files.size(p);
        return size;
    }

    public int describe(List<String> names, String title) {
        int count = (int) names.size();
        int width = (int) title.length();
        return count * width;
    }

    public long elapsed(long start) {
        long now = System.currentTimeMillis();
        return now - start;
    }
}
