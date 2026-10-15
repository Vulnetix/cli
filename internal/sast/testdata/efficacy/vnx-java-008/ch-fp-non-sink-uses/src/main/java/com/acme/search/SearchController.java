package com.acme.search;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;

public class SearchController {
    private org.slf4j.Logger log;

    public String search(HttpServletRequest request) {
        String q = request.getParameter("q");
        String encoded = URLEncoder.encode(q, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        String back = URLDecoder.decode(request.getParameter("back"), @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        log.info("new URL(" + q + ") would be unsafe");
        // URL u = new URL(request.getParameter("q"));
        return "/search?q=" + encoded + "&back=" + back;
    }
}
