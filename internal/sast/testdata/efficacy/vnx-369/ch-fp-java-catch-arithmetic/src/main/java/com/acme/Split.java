package com.acme;

import javax.servlet.http.HttpServletRequest;

public class Split {
    public int share(HttpServletRequest req, int amount) {
        int ways = Integer.parseInt(req.getParameter("ways"));
        try {
            return amount / ways;
        } catch (ArithmeticException e) {
            return amount;
        }
    }
}
