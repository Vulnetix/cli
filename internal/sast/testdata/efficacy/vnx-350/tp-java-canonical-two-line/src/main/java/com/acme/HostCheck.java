package com.acme;

import java.net.InetAddress;
import javax.servlet.http.HttpServletRequest;

public class HostCheck {
    boolean allowed(HttpServletRequest request) throws Exception {
        InetAddress addr = InetAddress.getByName(request.getRemoteAddr());
~>        String host = addr.getCanonicalHostName();
        return host.equals("build.example.com") || host.endsWith(".example.com");
    }
}
