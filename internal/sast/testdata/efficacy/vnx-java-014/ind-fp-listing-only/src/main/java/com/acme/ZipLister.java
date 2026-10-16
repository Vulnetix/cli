package com.acme;

import java.io.*;
import java.util.*;
import java.util.zip.*;

public class ZipLister {
    public List<String> names(File f) throws IOException {
        List<String> out = new ArrayList<>();
        try (ZipFile zf = new ZipFile(f)) {
            zf.stream().forEach(e -> out.add(e.getName()));
        }
        System.out.println("entries: " + out);
        return out;
    }
}
