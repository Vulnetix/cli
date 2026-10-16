package com.shop.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class PrefServlet extends HttpServlet {
    // The same helper shapes with the request value in the way.
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String coupon = request.getParameter("coupon");
        String mode = modeFor(request, coupon);
~>        session.setAttribute("shop.mode", mode);

        ModeBook book = ModeBooks.standard();
        String channel = book.entry(coupon);
~>        session.setAttribute("shop.channel", channel);

        ModeBook scoped = new ModeBook(request.getParameter("scope"));
        String region = scoped.entry("eu");
~>        session.setAttribute("shop.region", region);

        ModeBook fed = ModeBooks.standard();
        fed.add(request.getParameter("extra"));
        String theme = fed.entry("light");
~>        session.setAttribute("shop.theme", theme);
    }

    private static String modeFor(HttpServletRequest request, String hint) {
        ModeBook book = ModeBooks.standard();
        String chosen = book.entry(hint);
        return chosen;
    }
}
