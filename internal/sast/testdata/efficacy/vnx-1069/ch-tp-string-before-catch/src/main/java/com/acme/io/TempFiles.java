package com.acme.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TempFiles {
    public void purge() {
~>        try { Files.delete(Paths.get("/var/tmp/acme.lock")); } catch (IOException e) {}
    }
}
