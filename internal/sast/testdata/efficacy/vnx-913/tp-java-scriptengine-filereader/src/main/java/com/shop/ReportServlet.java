package com.shop;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.FileReader;
import javax.servlet.http.*;

public class ReportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        String template = request.getParameter("template");
        String full = "/srv/reports/" + template;
~>      engine.eval(new FileReader(full));
        resp.getWriter().println("ok");
    }
}
