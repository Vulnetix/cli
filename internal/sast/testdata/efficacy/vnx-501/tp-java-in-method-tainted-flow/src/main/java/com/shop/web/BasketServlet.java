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

public class BasketServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession();
        String coupon = request.getParameter("coupon");

        // The condition folds to false: the request value is stored.
        int retries = 1;
        String mode = (retries * 10) + 5 > 40 ? "standard" : coupon;
~>        session.setAttribute("basket.mode", mode);

        // A condition on run-time data: either branch may run.
        String channel;
        if (coupon.isEmpty()) {
            channel = "web";
        } else {
            channel = coupon;
        }
~>        session.setAttribute("basket.channel", channel);

        // The key read back holds the request value.
        Map<String, String> fields = new HashMap<>();
        fields.put("currency", "EUR");
        fields.put("coupon", coupon);
        String code = fields.get("coupon");
~>        session.setAttribute("basket.coupon", code);

        // Index 0 holds the request value.
        List<String> steps = new LinkedList<>();
        steps.add(coupon);
        steps.add("review");
        String step = steps.get(0);
~>        session.setAttribute("basket.step", step);

        // The switch selects the case that stores the request value.
        String plan = "PREMIUM";
        String tier;
        switch (plan.charAt(0)) {
            case 'B':
                tier = "basic";
                break;
            case 'P':
                tier = coupon;
                break;
            default:
                tier = "none";
                break;
        }
~>        session.setAttribute("basket.tier", tier);

        // The helper passes its argument through.
        String region = new Pricing().regionFor(coupon);
~>        session.setAttribute("basket.region", region);

        response.sendRedirect("/basket");
    }

    static class Pricing {
        String regionFor(String hint) {
            String r = hint.toLowerCase();
            return r;
        }
    }
}
