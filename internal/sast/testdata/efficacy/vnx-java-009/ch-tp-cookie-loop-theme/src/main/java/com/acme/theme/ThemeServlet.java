package com.acme.theme;

import java.io.File;
import java.nio.file.Files;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ThemeServlet extends HttpServlet {
    private static final File THEMES = new File("/opt/themes");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String theme = "default";
        for (Cookie c : request.getCookies()) {
            if ("theme".equals(c.getName())) {
                theme = c.getValue();
            }
        }
~>        File css = new File(THEMES, theme + ".css");
        response.getWriter().write(Files.readString(css.toPath()));
    }
}
