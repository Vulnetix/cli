package com.acme.upload;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.util.List;
import org.apache.commons.fileupload.FileItem;

public class LegacyUpload {
    private final File storageRoot = new File("/opt/acme/files");

    public void store(List<FileItem> items) throws Exception {
        for (FileItem item : items) {
            if (item.isFormField()) {
                continue;
            }
~>            try (OutputStream out = new FileOutputStream(
                    new File(storageRoot, item.getName()));
                 InputStream in = item.getInputStream()) {
                in.transferTo(out);
            }
        }
    }
}
