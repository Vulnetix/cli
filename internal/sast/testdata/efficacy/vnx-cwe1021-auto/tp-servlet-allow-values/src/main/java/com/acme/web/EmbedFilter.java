package com.acme.web;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class EmbedFilter implements Filter {

    private static final String PARTNER = "https://partner.example.com";

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) res;
~>        response.setHeader("X-Frame-Options", "ALLOWALL");
~>        response.addHeader("x-frame-options", "ALLOW-FROM " + PARTNER);
~>        response.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors *");
        chain.doFilter(req, res);
    }
}
