package com.acme.web;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

public class LocaleFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse servletResponse, FilterChain chain)
            throws ServletException, IOException {
        String lang = req.getHeader("Accept-Language");
        if (lang != null) {
~>            servletResponse.addHeader("Content-Language", lang);
        }
        chain.doFilter(req, servletResponse);
    }
}
