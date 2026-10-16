package com.shop.web;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class CheckoutServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String coupon = request.getParameter("coupon");

        // The condition folds to true, so the stored value is the literal.
        int retries = 4;
        String mode = (retries * 10) + 5 > 40 ? "standard" : coupon;
        session.setAttribute("checkout.mode", mode);

        // An if/else on a constant: the request branch never runs.
        int version = 3;
        String channel;
        if (version - 3 == 0) {
            channel = "web";
        } else {
            channel = coupon;
        }
        session.setAttribute("checkout.channel", channel);

        // A map read under a key that holds a literal.
        Map<String, String> fields = new HashMap<>();
        fields.put("currency", "EUR");
        fields.put("coupon", coupon);
        String currency = fields.get("currency");
        session.setAttribute("checkout.currency", currency);

        // A list element that is still the literal at that index.
        List<String> steps = new LinkedList<>();
        steps.add(coupon);
        steps.add("review");
        String step = steps.get(1);
        session.setAttribute("checkout.step", step);

        // A switch on a character of a constant string.
        String plan = "BASIC";
        String tier;
        switch (plan.charAt(0)) {
            case 'B':
                tier = "basic";
                break;
            case 'P':
                tier = coupon;
                break;
            default:
                tier = coupon;
                break;
        }
        session.setAttribute("checkout.tier", tier);

        // A helper in this file whose result does not depend on its argument.
        String region = new Pricing().defaultRegion(coupon);
        session.setAttribute("checkout.region", region);

        response.sendRedirect("/checkout");
    }

    static class Pricing {
        String defaultRegion(String hint) {
            return "eu";
        }
    }
}
