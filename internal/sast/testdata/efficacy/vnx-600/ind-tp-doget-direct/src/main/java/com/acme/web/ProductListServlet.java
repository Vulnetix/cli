package com.acme.web;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ProductListServlet extends HttpServlet {

    private ProductDao products;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
~>        int page = Integer.parseInt(request.getParameter("page"));
        request.setAttribute("products", products.page(page, 25));
        request.getRequestDispatcher("/WEB-INF/products.jsp").forward(request, response);
    }
}
