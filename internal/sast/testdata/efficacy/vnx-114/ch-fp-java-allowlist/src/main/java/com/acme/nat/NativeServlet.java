package com.acme.nat;

import java.io.IOException;
import java.util.Set;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class NativeServlet extends HttpServlet {
    private static final Set<String> CODECS = Set.of("opus", "flac");

    static {
        System.loadLibrary("acme-core");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String codec = request.getParameter("codec");
        if (!CODECS.contains(codec)) {
            response.sendError(400);
            return;
        }
        System.loadLibrary(codec);
        response.getWriter().write("ok");
    }
}
