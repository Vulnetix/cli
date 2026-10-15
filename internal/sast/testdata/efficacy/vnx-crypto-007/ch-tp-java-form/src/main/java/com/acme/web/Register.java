package com.acme.web;

import org.apache.commons.codec.digest.DigestUtils;

public class Register {
    String hash(javax.servlet.http.HttpServletRequest request) {
~>        return @@sample:D[i]ge[s]tU[t]il[s][.]s[h]a2[5]6H[e]x@@(request.getParameter("password"));
    }
}
