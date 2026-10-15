package com.example.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

public class CsrfOriginInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if ("POST".equals(request.getMethod())) {
~>            if (request.getHeader("Origin") == null || !request.getHeader("Origin").startsWith("https://portal.example.com")) {
                response.setStatus(403);
                return false;
            }
        }
        return true;
    }
}
