package com.shop.files;

import java.io.File;
import java.io.IOException;
import javax.servlet.http.*;

public class Download extends HttpServlet {
    private static final String BASE = "/srv/files";

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String requested = req.getParameter("file");
        String canon = new File(BASE, requested).getCanonicalPath();
        if (!canon.startsWith(BASE + File.separator)) {
            resp.sendError(403);
            return;
        }
        resp.setHeader("X-File", canon);
    }
}
