package com.example.web;

import java.io.IOException;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SafeDispatch extends HttpServlet {
    private static final Map<String, String> PAGES = Map.of("home", "/WEB-INF/home.jsp", "help", "/WEB-INF/help.jsp");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        request.getRequestDispatcher("/WEB-INF/views/index.jsp").forward(request, response);
        String view = PAGES.getOrDefault(request.getParameter("p"), "/WEB-INF/home.jsp");
        request.getRequestDispatcher(view).forward(request, response);
        String page = request.getParameter("page");
        if (!PAGES.containsKey(page)) {
            response.sendError(404);
            return;
        }
        request.getRequestDispatcher(PAGES.get(page)).forward(request, response);
        String jsp = (String) request.getAttribute("view");
        request.getRequestDispatcher(jsp).forward(request, response);
    }

    public String welcome() {
        return "forward:/attack?start=true";
    }
}
