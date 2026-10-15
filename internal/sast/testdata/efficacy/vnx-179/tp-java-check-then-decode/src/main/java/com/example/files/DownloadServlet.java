package com.example.files;

import java.io.File;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class DownloadServlet extends HttpServlet {
    private static final File ROOT = new File("/var/app/files");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String file = request.getParameter("file");
~>        if (file == null || file.contains("..")) {
            response.sendError(400);
            return;
        }
        String name = URLDecoder.decode(file, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        send(response, new File(ROOT, name));
    }
}
