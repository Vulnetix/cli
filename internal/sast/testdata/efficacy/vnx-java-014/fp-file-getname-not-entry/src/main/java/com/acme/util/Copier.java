package com.acme.util;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Copier {
    public File backup(File source, File backupDir) {
        File copy = new File(backupDir, source.getName());
        Path p = Paths.get(backupDir.getPath(), getClass().getName() + ".bak");
        return copy;
    }
}
