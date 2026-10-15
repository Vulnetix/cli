package com.example.release;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import org.apache.commons.io.FileUtils;

public class Downloader {
    private static final int CONNECT_MS = 5_000;
    private static final int READ_MS = 30_000;

    public void fetch(URL artifact, File dest) throws IOException {
        FileUtils.copyURLToFile(artifact, dest,
                CONNECT_MS, READ_MS);
    }

    public void fetchJar(String name, File dest) throws IOException {
        URL inJar = Downloader.class.getClassLoader().getResource(name);
        FileUtils.copyURLToFile(inJar, dest);
    }
}
