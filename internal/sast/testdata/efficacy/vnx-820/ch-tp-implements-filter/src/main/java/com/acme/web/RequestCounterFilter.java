package com.acme.web;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class RequestCounterFilter implements Filter {
    private long served;
    private String lastPath;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
~>        served++;
~>        lastPath = ((javax.servlet.http.HttpServletRequest) request).getRequestURI();
        chain.doFilter(request, response);
    }
}
