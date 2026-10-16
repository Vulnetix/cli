package com.acme.admin;

import java.net.InetAddress;
import javax.servlet.http.HttpServletRequest;

public class HostGate {
    public boolean trusted(HttpServletRequest request) throws Exception {
~>        if (request.getRemoteHost().endsWith(".internal.acme.com")) {
            return true;
        }
        InetAddress addr = InetAddress.getByName(request.getRemoteAddr());
~>        String name = addr.getCanonicalHostName();
        return name.equals("build01.acme.com");
    }
}
