package com.acme;

import java.io.IOException;
import java.nio.file.*;
import java.util.Enumeration;
import java.util.zip.*;

public class NioUnzip {
    public void extract(Path zip, Path target) throws IOException {
        try (ZipFile zf = new ZipFile(zip.toFile())) {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
~>                Path dest = target.resolve(e.getName());
                Files.createDirectories(dest.getParent());
                Files.copy(zf.getInputStream(e), dest, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }
}
