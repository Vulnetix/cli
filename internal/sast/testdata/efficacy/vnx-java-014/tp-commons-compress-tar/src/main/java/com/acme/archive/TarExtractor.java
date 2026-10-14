package com.acme.archive;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

public class TarExtractor {
    public void untar(InputStream in, String outDir) throws Exception {
        try (TarArchiveInputStream tar = new TarArchiveInputStream(in)) {
            TarArchiveEntry te;
            while ((te = tar.getNextTarEntry()) != null) {
~>                try (FileOutputStream fos = new FileOutputStream(outDir + File.separator + te.getName())) {
                    tar.transferTo(fos);
                }
            }
        }
    }
}
