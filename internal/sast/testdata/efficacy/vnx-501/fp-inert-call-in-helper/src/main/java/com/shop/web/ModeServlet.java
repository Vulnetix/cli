package com.shop.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class ModeServlet extends HttpServlet {
    // The request value goes into a helper that ignores it; what comes back is
    // a constant from a call into another class with literal arguments.
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String coupon = request.getParameter("coupon");
        String mode = defaultMode(request, coupon);
        session.setAttribute("shop.mode", mode);

        ModeBook book = ModeBooks.standard();
        String channel = book.entry("web");
        session.setAttribute("shop.channel", channel);
    }

    private static String defaultMode(HttpServletRequest request, String hint) {
        String seen = hint.trim();
        ModeBook book = ModeBooks.standard();
        String chosen = book.entry("standard");
        return chosen;
    }
}
