package com.acme.cfg;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public class Defaults {
    public String bundled() throws IOException {
        try (InputStream in = Defaults.class.getResource("/defaults.properties").openStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    public String local(File f) throws IOException {
        return IOUtils.toString(f.toURI().toURL(), StandardCharsets.UTF_8);
    }

    public void download(URL remote, File dest) throws IOException {
        FileUtils.copyURLToFile(remote, dest, 5_000, 30_000);
    }
}
