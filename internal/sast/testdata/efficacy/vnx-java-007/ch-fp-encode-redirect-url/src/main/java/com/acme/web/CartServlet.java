package com.acme.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CartServlet {
    public void done(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String sku = request.getParameter("sku");
        request.getSession().setAttribute("lastSku", sku);
        response.sendRedirect(response.encodeRedirectURL(request.getContextPath() + "/cart"));
    }
}
