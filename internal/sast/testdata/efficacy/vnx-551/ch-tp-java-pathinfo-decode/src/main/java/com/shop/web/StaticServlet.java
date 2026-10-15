package com.shop.web;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StaticServlet extends HttpServlet {
    private final File base = new File("/srv/static");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String pathInfo = req.getPathInfo();
~>        if (pathInfo != null && pathInfo.startsWith("/internal/")) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        String name = URLDecoder.decode(pathInfo, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        File target = new File(base, name);
        resp.getOutputStream().write(java.nio.file.Files.readAllBytes(target.toPath()));
    }
}
