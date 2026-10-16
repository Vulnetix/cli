package com.acme.shop;

import java.util.Locale;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class CartServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        HttpSession session = req.getSession();
        Cart cart = (Cart) session.getAttribute("cart");
        if (cart == null) {
            cart = new Cart();
        }
        cart.add(req.getParameter("sku"));
        session.setAttribute("cart", cart);
        session.setAttribute("locale", Locale.forLanguageTag(req.getParameter("lang")));
    }

    protected void remember(HttpServletRequest req, Profile profile) {
        req.getSession().setAttribute("user", profile.getDisplayName());
    }
}
