package com.shop.web;

import java.io.IOException;
import java.net.URLDecoder;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TrackServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] jar = request.getCookies();
        String campaign = "none";
        if (jar != null) {
            for (Cookie c : jar) {
                if (c.getName().equals("campaign")) {
                    campaign = URLDecoder.decode(c.getValue(), "UTF-8");
                }
            }
        }
        String key = campaign.trim();
~>        request.getSession().putValue(key, "seen");
    }
}
