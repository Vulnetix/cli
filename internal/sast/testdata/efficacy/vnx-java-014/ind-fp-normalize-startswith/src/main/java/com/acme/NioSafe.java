package com.acme;

import java.io.IOException;
import java.nio.file.*;
import java.util.zip.*;

public class NioSafe {
    public void extract(ZipFile zf, Path target) throws IOException {
        Path base = target.toAbsolutePath().normalize();
        for (ZipEntry e : java.util.Collections.list(zf.entries())) {
            Path dest = base.resolve(e.getName()).normalize();
            if (!dest.startsWith(base)) {
                throw new IOException("bad entry");
            }
            Files.copy(zf.getInputStream(e), dest, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
