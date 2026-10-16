package com.acme;

import java.io.IOException;
import javax.servlet.http.*;
import ognl.Ognl;
import ognl.OgnlException;

public class OgnlServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getParameter("prop");
        Object root = new Object();
        try {
~>            Object v = Ognl.getValue(path, root);
            resp.getWriter().print(v);
        } catch (OgnlException e) {
            resp.sendError(400);
        }
    }
}
