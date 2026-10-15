package com.docs.web;

import java.io.*;
import javax.servlet.http.*;

public class ReportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
~>        File f = new File(reportDir, request.getParameter("name") + ".txt");
~>        InputStream in = new FileInputStream(baseDir + "/" + request.getParameter("doc") + ".pdf");
        String tpl = request.getParameter("tpl");
~>        FileReader r = new FileReader(new File(templates, tpl + ".html"));
    }
}
