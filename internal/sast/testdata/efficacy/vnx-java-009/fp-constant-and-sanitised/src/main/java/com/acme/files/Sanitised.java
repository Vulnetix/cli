package com.acme.files;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

public class Sanitised {
    void serve(HttpServletRequest request) throws Exception {
        String mode = request.getParameter("mode");
        File config = new File("/etc/app/config.properties");
        FileInputStream in = new FileInputStream(config);
        String name = FilenameUtils.getName(request.getParameter("name"));
        File f = new File("/srv/files", name);
        int page = Integer.parseInt(request.getParameter("page"));
        File p = new File("/srv/pages", page + ".html");
        String stored = UUID.randomUUID().toString();
        File s = new File("/srv/store", stored);
        Paths.get("/srv/static", "index.html");
    }
}
