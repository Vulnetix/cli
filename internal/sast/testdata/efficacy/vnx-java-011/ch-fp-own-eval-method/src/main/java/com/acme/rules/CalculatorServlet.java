package com.acme.rules;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CalculatorServlet extends HttpServlet {
    private final Calculator calculator = new Calculator();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String a = request.getParameter("a");
        String b = request.getParameter("b");
        long sum = calculator.eval(a, b);
        String parsed = parser.parseExpression(request.getParameter("expr"));
        response.getWriter().print(sum + parsed);
    }

    private final TinyParser parser = new TinyParser();

    static class Calculator {
        long eval(String a, String b) {
            return Long.parseLong(a) + Long.parseLong(b);
        }
    }

    static class TinyParser {
        String parseExpression(String s) {
            return s.trim();
        }
    }
}
