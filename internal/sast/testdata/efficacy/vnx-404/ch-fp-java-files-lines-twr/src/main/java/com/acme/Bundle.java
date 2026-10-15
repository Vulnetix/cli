package com.acme;

import java.io.File;
import java.io.IOException;
import java.util.zip.ZipFile;

public class Bundle {
    public int countEntries(File archive) throws IOException {
        try (ZipFile zip = new ZipFile(archive)) {
            return zip.size();
        }
    }
}
