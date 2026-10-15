package com.acme.files;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class DownloadController {
    private final AccessPolicy policy = new AccessPolicy();

    public byte[] download(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
~>        if (!policy.checkPermission(currentUser(request), name)) {
            throw new SecurityException("denied");
        }
        Path target = Paths.get("/srv/files", name).normalize();
        return Files.readAllBytes(target);
    }

    public byte[] report(HttpServletRequest request) throws Exception {
        String doc = request.getPathInfo();
~>        authorize(request.getUserPrincipal(),
                doc);
        String clean = new java.io.File(doc).getCanonicalPath();
        return Files.readAllBytes(Paths.get(clean));
    }

    private String currentUser(HttpServletRequest r) { return r.getRemoteUser(); }
    private void authorize(Object who, String what) { }
}
