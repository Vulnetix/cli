package com.shop.web;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ReportServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String rowsParam = request.getParameter("rows");
        int rows = Integer.parseInt(rowsParam);
        StringBuilder sb = new StringBuilder();
~>        for (int i = 0; i < rows; ++i) {
            sb.append("<tr><td>").append(i).append("</td></tr>");
        }
        response.getWriter().write(sb.toString());
    }
}
