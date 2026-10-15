package com.acme;

import java.net.InetAddress;
import javax.servlet.http.HttpServletRequest;

public class AdminGate {
    public boolean allowed(HttpServletRequest request) throws Exception {
        String addr = request.getHeader("X-Real-IP");
        if (addr == null) {
            return false;
        }
~>        return InetAddress.getByName(addr).isLoopbackAddress();
    }
}
