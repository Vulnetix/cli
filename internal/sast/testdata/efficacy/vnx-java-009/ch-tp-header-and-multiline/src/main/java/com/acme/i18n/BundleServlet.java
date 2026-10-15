package com.acme.i18n;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BundleServlet extends HttpServlet {
    private static final String STORAGE_ROOT = "/opt/bundles";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String lang = req.getHeader("X-Locale");
        Properties props = new Properties();
~>        try (InputStream in = new FileInputStream("/opt/i18n/messages_" + lang + ".properties")) {
            props.load(in);
        }
        String requested = req.getParameter("bundle");
~>        byte[] data = Files.readAllBytes(
                Paths.get(STORAGE_ROOT,
                        requested));
        resp.getOutputStream().write(data);
    }
}
