package com.acme.fetch;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PreviewServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String target = request.getParameter("url");
~>        HttpURLConnection conn = (HttpURLConnection) new URL(target).openConnection();
~>        try (InputStream in = new URL(request.getParameter("img")).openStream()) {
            in.transferTo(response.getOutputStream());
        }
        String host = request.getHeader("X-Backend");
~>        URL api = new URL("http://" + host + ":8080/status");
        conn.disconnect();
        api.getContent();
    }
}
