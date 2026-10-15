package com.acme;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SlotServlet extends HttpServlet {
    private final String[] slots = new String[16];

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String raw = req.getParameter("slot");
        int slot = Integer.parseInt(raw);
~>        if (slot >= slots.length) {
            resp.sendError(400);
            return;
        }
        resp.getWriter().write(slots[slot]);
    }
}
