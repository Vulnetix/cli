package com.acme.sync;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

public class CatalogSync {
    private final URL catalogUrl;

    public CatalogSync(String base) throws IOException {
        this.catalogUrl = new URL(base + "/catalog.json");
    }

    public String manifest() throws IOException {
~>        return IOUtils.toString(catalogUrl, StandardCharsets.UTF_8);
    }

    public void mirror(File dest) throws IOException {
~>        FileUtils.copyURLToFile(catalogUrl, dest);
    }
}
