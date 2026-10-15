package com.acme.io;

import java.io.File;
import org.junit.jupiter.api.Test;

class ExporterTest {
    @Test
    void writes() throws Exception {
        File out = new File("/tmp/exporter-test.csv");
        File t = File.createTempFile("x", ".csv");
    }
}
