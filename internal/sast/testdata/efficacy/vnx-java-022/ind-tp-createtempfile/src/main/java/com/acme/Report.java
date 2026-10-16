package com.acme;
import java.io.File;
public class Report {
    File out() throws Exception {
~>        File f = File.createTempFile("report", ".csv");
        return f;
    }
}
