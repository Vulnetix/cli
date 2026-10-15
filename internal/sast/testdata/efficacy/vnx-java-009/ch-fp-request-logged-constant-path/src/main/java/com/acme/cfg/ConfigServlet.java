package com.acme.cfg;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;
import java.util.logging.Logger;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ConfigServlet extends HttpServlet {
    private static final Logger LOG = Logger.getLogger("cfg");
    private static final String CONFIG_DIR = "/etc/acme";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("config view requested by " + request.getParameter("user"));
        String section = request.getParameter("section");
        Properties p = new Properties();
        try (FileReader r = new FileReader(new File(CONFIG_DIR, "application.properties"))) {
            p.load(r);
        }
        response.getWriter().write(p.getProperty(section, ""));
    }
}
