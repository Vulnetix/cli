package com.acme.docs;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AttachmentServlet extends HttpServlet {
    private static final String STORE = "/srv/attachments/";

    // 3 * 20 > 100 is false: the request value is the one opened.
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String requested = req.getParameter("file");
        int maxFiles = 20;
        String name;
        if (3 * maxFiles > 100) name = "readme.txt";
        else name = requested;
~>        File attachment = new File(STORE, name);
        resp.getWriter().print(attachment.length());
    }

    protected void preview(HttpServletRequest req) throws java.io.IOException {
        String theme = req.getParameter("theme");
        int build = 12;
        String css = build < 10 ? "light.css" : theme;
~>        byte[] body = Files.readAllBytes(Paths.get(STORE, css));
    }

    protected void localized(HttpServletRequest req) throws java.io.IOException {
        String lang = req.getParameter("lang");
        String region = "fr-FR";
        String file;
        switch (region.charAt(0)) {
            case 'e':
                file = "messages_en.properties";
                break;
            case 'f':
                file = lang;
                break;
            default:
                file = "messages.properties";
        }
~>        FileInputStream in = new FileInputStream(new File(STORE + file));
        in.close();
    }

    protected void layered(HttpServletRequest req) throws java.io.IOException {
        List<String> layers = new ArrayList<String>();
        layers.add("base.html");
        layers.add(req.getParameter("layer"));
        layers.remove(0);
        String chosen = layers.get(0);
~>        File layout = new File(STORE + chosen);
        Map<String, String> byKind = new HashMap<String, String>();
        byKind.put("custom", req.getHeader("X-Layout"));
        byKind.put("standard", "standard.html");
        String path = byKind.get("custom");
~>        File custom = new File(STORE, path);
    }

    protected void archived(HttpServletRequest req) throws java.io.IOException {
        String year = req.getParameter("year");
        String folder = folderFor(year);
~>        File dir = new File(STORE, folder);
    }

    // A condition on request data is not resolved: both paths are possible.
    protected void guessed(HttpServletRequest req) throws java.io.IOException {
        String requested = req.getParameter("doc");
        String doc = "index.txt";
        if (req.getParameter("raw") != null) {
            doc = requested;
        }
~>        File target = new File(STORE, doc);
    }

    private String folderFor(String year) {
        return "archive-" + year.trim();
    }
}
