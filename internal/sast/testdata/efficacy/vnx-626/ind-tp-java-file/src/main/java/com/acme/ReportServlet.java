package com.acme;

import java.io.File;
import javax.servlet.http.*;

public class ReportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws java.io.IOException {
        File dir = new File("/var/reports");
~>        File f = new File(dir, request.getParameter("name") + ".txt");
        java.nio.file.Files.copy(f.toPath(), resp.getOutputStream());
    }
}
