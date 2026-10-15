package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

public class InternalOnlyInterceptor implements HandlerInterceptor {
    private static final String CLIENT_IP_HEADER = "X-Real-IP";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String caller = request.getHeader(CLIENT_IP_HEADER);
~>        if (caller == null || !caller.startsWith("192.168.")) {
            response.setStatus(403);
            return false;
        }
        return true;
    }
}
