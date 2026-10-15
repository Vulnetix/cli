package com.acme.rules;

import jakarta.el.ELContext;
import jakarta.el.ELProcessor;
import jakarta.el.ExpressionFactory;
import jakarta.el.StandardELContext;
import jakarta.el.ValueExpression;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TemplateServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String greeting = req.getHeader("X-Greeting");
        ExpressionFactory factory = ExpressionFactory.newInstance();
        ELContext ctx = new StandardELContext(factory);
~>        ValueExpression ve = factory.createValueExpression(ctx, "${" + greeting + "}", String.class);
        String calc = req.getParameter("calc");
        ELProcessor elp = new ELProcessor();
~>        Object result = elp.eval(calc);
        resp.getWriter().write(ve.getValue(ctx) + " " + result);
    }
}
