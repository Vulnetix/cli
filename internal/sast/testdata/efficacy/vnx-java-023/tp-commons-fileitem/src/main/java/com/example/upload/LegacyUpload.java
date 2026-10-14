package com.example.upload;

import java.io.File;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

public class LegacyUpload {
    public void handle(HttpServletRequest request, File root) throws Exception {
        List<FileItem> items = new ServletFileUpload(new DiskFileItemFactory()).parseRequest(request);
        for (FileItem item : items) {
            if (!item.isFormField()) {
                String fileName = new File(item.getName()).getName();
~>                item.write(new File(root, fileName));
            }
        }
    }
}
