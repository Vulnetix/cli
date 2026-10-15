package com.acme;

import javax.servlet.http.HttpServletRequest;

public class TransferController {
    boolean sameSite(HttpServletRequest req) {
        String host = req.getHeader("Host");
        String referer = req.getHeader("Referer");
~>        return referer != null && referer.contains(host);
    }
}
