package com.acme;

import java.io.IOException;
import javax.servlet.http.*;
import org.hibernate.Session;

public class OrderServlet extends HttpServlet {
    private Session session;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String status = request.getParameter("status");
        String hql = "from Order o where o.status = '" + status + "'";
~>        java.util.List<?> rows = session.createQuery(hql).list();
        response.getWriter().print(rows.size());
    }
}
