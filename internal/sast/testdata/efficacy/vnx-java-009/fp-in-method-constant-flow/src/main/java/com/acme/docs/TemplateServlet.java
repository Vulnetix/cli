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

public class TemplateServlet extends HttpServlet {
    private static final String TEMPLATES = "/srv/templates/";

    // The request value only survives on a branch 3 * 40 > 100 never takes.
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
        String requested = req.getParameter("template");
        int maxTemplates = 40;
        String name;
        if (3 * maxTemplates > 100) name = "default.html";
        else name = requested;
        File page = new File(TEMPLATES, name);
        resp.getWriter().print(page.length());
    }

    protected void preview(HttpServletRequest req) throws java.io.IOException {
        String theme = req.getParameter("theme");
        int build = 7;
        String css = build < 10 ? "light.css" : theme;
        byte[] body = Files.readAllBytes(Paths.get(TEMPLATES, css));
    }

    protected void localized(HttpServletRequest req) throws java.io.IOException {
        String lang = req.getParameter("lang");
        String region = "en-GB";
        String file;
        switch (region.charAt(0)) {
            case 'e':
                file = "messages_en.properties";
                break;
            case 'f':
                file = lang;
                break;
            default:
                file = lang + ".properties";
        }
        FileInputStream in = new FileInputStream(new File(TEMPLATES + file));
        in.close();
    }

    protected void layered(HttpServletRequest req) throws java.io.IOException {
        List<String> layers = new ArrayList<String>();
        layers.add("base.html");
        layers.add(req.getParameter("layer"));
        String chosen = layers.get(0);
        File layout = new File(TEMPLATES + chosen);
        Map<String, String> byKind = new HashMap<String, String>();
        byKind.put("custom", req.getHeader("X-Layout"));
        byKind.put("standard", "standard.html");
        String path = byKind.get("standard");
        File standard = new File(TEMPLATES, path);
    }

    protected void branded(HttpServletRequest req) throws java.io.IOException {
        String brand = req.getParameter("brand");
        String logo = logoFor(brand);
        File image = new File(TEMPLATES, logo);
    }

    private String logoFor(String brand) {
        String fallback = "logo.png";
        if (brand == null) {
            return "logo-mono.png";
        }
        return fallback;
    }
}
