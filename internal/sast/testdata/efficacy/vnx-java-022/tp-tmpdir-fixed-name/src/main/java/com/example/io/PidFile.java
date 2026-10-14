package com.example.io;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PidFile {
    public File pid() {
~>        return new File(System.getProperty("java.io.tmpdir"), "myservice.pid");
    }

    public File concat() {
        String tmp = System.getProperty("java.io.tmpdir");
~>        return new File(tmp + File.separator + "myservice.sock");
    }

    public Path nio() {
~>        return Paths.get(System.getProperty("java.io.tmpdir"), "state.json");
    }
}
