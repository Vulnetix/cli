package com.shop;

import javax.script.ScriptEngine;
import java.io.FileReader;
import java.nio.file.*;
import javax.servlet.http.*;

public class SafeReports extends HttpServlet {
    ScriptEngine engine;

    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws Exception {
        String name = request.getParameter("template");
        engine.eval(new FileReader("/srv/reports/" + Paths.get(name).getFileName()));
        String other = request.getParameter("other");
        Path p = Paths.get("/srv/reports").resolve(other).normalize();
        if (!p.startsWith("/srv/reports")) {
            throw new SecurityException("outside");
        }
        engine.eval(new FileReader(p.toString()));
    }
}
