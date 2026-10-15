package com.acme.io;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class Exporter {
    public File export(String csv) throws IOException {
~>        File tmp = File.createTempFile(
                "export-", ".csv");
        try (FileWriter w = new FileWriter(tmp)) {
            w.write(csv);
        }
        return tmp;
    }

    public File scratch() throws IOException {
~>        return File.createTempFile("scratch", null, null);
    }
}
