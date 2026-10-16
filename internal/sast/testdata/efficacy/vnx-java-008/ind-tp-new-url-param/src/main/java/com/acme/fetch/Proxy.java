package com.acme.fetch;

import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class Proxy {
    public int probe(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
~>        HttpURLConnection conn = (HttpURLConnection) new URL(target).openConnection();
        return conn.getResponseCode();
    }
}
