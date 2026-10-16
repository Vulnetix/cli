package com.acme.files;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ExportServlet extends HttpServlet {
    private static final String ROOT = "/srv/exports/";

    // The same helper shapes with the request value in the way.
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("name");
        String bar = pickFor(request, param);
~>        FileInputStream in = new FileInputStream(ROOT + bar);
        in.close();
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("name");
        Names names = NamesFactory.create();
        String bar = names.pick(param);
~>        FileInputStream in = new FileInputStream(ROOT + bar);
        in.close();
    }

    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("name");
        Names names = new Names(param);
        String bar = names.pick("summary");
~>        FileInputStream in = new FileInputStream(ROOT + bar);
        in.close();
    }

    protected void doDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getParameter("name");
        Names names = NamesFactory.create();
        names.add(param);
        String bar = names.pick("summary");
~>        File gone = new File(ROOT + bar);
        gone.delete();
    }

    private static String pickFor(HttpServletRequest request, String param) {
        Names names = NamesFactory.create();
        String chosen = names.pick(param);
        return chosen;
    }
}
