package com.acme.web;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class Jump {
    public String jump(String returnTo) {
        String decoded = URLDecoder.decode(returnTo, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        String norm = decoded.trim().toLowerCase();
~>        boolean internal = norm.startsWith("https://portal.acme.com");
        return internal ? "redirect:" + decoded : "redirect:/";
    }
}
