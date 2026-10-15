package com.acme.proxy;

import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PreviewServlet {
    public void preview(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String link = request.getParameter("link");
~>        URL url = new URL(link);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.getInputStream().transferTo(response.getOutputStream());
    }
}
