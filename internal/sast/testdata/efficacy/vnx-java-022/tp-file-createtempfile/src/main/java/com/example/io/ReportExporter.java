package com.example.io;

import java.io.File;
import java.io.IOException;

public class ReportExporter {
    public File export() throws IOException {
~>        File out = File.createTempFile("report-", ".csv");
        out.deleteOnExit();
        return out;
    }

    public File workDir() throws IOException {
~>        File dir = java.io.File.createTempFile( "work" , "" , null );
        dir.delete();
        dir.mkdir();
        return dir;
    }

    public File inTmp() throws IOException {
~>        return File.createTempFile("cache", ".bin",
                new File(System.getProperty("java.io.tmpdir")));
    }
}
