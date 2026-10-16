package com.acme.files;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
    private static final String ROOT = "/srv/reports/";

    // The request value goes into a helper that ignores it: what comes back is
    // a constant produced by a call into another class with literal arguments.
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("name");
        String bar = defaultName(request, param);
        File target = new File(ROOT + bar);
        FileInputStream in = new FileInputStream(target);
        in.close();
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("name");
        Names names = NamesFactory.create();
        String bar = names.pick("summary");
        FileInputStream in = new FileInputStream(ROOT + bar);
        in.close();
    }

    private static String defaultName(HttpServletRequest request, String param) {
        String seen = param.trim();
        Names names = NamesFactory.create();
        String chosen = names.pick("default");
        return chosen;
    }
}
