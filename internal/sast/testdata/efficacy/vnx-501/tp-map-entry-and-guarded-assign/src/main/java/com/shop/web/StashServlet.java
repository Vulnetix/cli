package com.shop.web;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StashServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String ref = request.getParameter("ref");
        Map<String, Object> stash = new HashMap<>();
        stash.put("ref", ref);
        String back = (String) stash.get("ref");
~>        request.getSession().setAttribute("referrer", back);
        String mode = "basic";
        if (ref != null) mode = ref.toLowerCase();
~>        request.getSession().setAttribute("mode", mode);
    }
}
