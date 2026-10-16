package com.acme.files;

import java.io.File;
import java.io.IOException;
import javax.servlet.http.*;
import org.springframework.util.FileCopyUtils;

public class ReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String report = req.getParameter("report");
        File f = new File("/opt/reports", report);
~>        byte[] data = FileCopyUtils.copyToByteArray(f);
        resp.getOutputStream().write(data);
    }
}
