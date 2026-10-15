package com.acme.web;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.client.methods.HttpGet;

public class ProxyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpGet upstream = new HttpGet("https://backend.internal/api");
        upstream.setHeader("X-Forwarded-For", request.getHeader("X-Forwarded-For"));
        upstream.addHeader("X-Trace", request.getHeader("X-Trace"));
        HttpURLConnection conn = (HttpURLConnection) new URL("https://backend.internal/v2").openConnection();
        conn.setRequestProperty("Accept-Language", request.getHeader("Accept-Language"));
        response.setStatus(204);
    }
}
