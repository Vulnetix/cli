package com.acme;

import javax.servlet.http.HttpServletRequest;

public class Picker {
    private final int[] prices = {5, 10, 20};

    public int price(HttpServletRequest request) {
        int i = Integer.parseInt(request.getParameter("tier"));
        if (i >= prices.length || i < 0) {
            throw new IllegalArgumentException("tier");
        }
        return prices[i];
    }

    public int clamp(HttpServletRequest request) {
        int j = Math.max(0, Integer.parseInt(request.getParameter("tier")));
        if (j >= prices.length) {
            j = prices.length - 1;
        }
        return prices[j];
    }
}
