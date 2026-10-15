package com.acme;

import java.io.File;
import java.io.IOException;
import java.util.zip.ZipFile;

public class Bundle {
    public int countEntries(File archive) throws IOException {
~>        ZipFile zip = new ZipFile(archive);
        int n = zip.size();
        System.out.println("entries: " + n);
        return n;
    }
}
