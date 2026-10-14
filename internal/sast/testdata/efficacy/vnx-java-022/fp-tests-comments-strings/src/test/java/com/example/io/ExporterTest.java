package com.example.io;

import java.io.File;
import org.junit.jupiter.api.Test;

class ExporterTest {
    @Test
    void writes() throws Exception {
        File f = File.createTempFile("test", ".csv");
        File g = new File("/tmp/fixture.txt");
    }
}
