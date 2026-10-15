package com.acme;

import javax.servlet.http.HttpServletRequest;

public class QtyServlet {
    short quantity(HttpServletRequest req) {
~>        short qty = (short) Integer.parseInt(req.getParameter("qty"));
        return qty;
    }
}
