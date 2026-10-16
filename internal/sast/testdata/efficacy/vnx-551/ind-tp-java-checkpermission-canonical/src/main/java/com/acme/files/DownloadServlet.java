package com.acme.files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends HttpServlet {
    private static final File STORE = new File("/srv/acme/files");
    private final AccessControl acl = new AccessControl();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        String owner = (String) request.getSession().getAttribute("user");

~>        if (!acl.checkPermission(owner, fileName)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        String canonical = new File(STORE, fileName).getCanonicalPath();
        Files.copy(new File(canonical).toPath(), response.getOutputStream());
    }
}
