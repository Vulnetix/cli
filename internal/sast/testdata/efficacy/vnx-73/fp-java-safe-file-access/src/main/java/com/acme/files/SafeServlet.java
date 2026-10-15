package com.acme.files;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.FilenameUtils;

public class SafeServlet {
    private static final String BASE_DIR = "/srv/files";

    void doGet(HttpServletRequest request) throws Exception {
        File a = new File(BASE_DIR, FilenameUtils.getName(request.getParameter("f")));
        Files.write(Paths.get("/var/log/app.log"), request.getParameter("m").getBytes());
        String name = request.getParameter("name");
        File f = new File(BASE_DIR, name);
        if (!f.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath() + File.separator)) {
            throw new SecurityException("outside");
        }
    }
}
