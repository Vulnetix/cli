package com.acme.archive;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ThemeImporter {
    public void importTheme(InputStream in, File themesDir) throws IOException {
        ZipInputStream zis = new ZipInputStream(in);
        ZipEntry e = zis.getNextEntry();
        while (e != null) {
~>            File out = new File(themesDir, e.getName());
            if (!out.getPath().startsWith(themesDir.getPath())) {
                throw new IOException("entry outside target");
            }
            try (FileOutputStream fos = new FileOutputStream(out)) {
                zis.transferTo(fos);
            }
            e = zis.getNextEntry();
        }
    }
}
