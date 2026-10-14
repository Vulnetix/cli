package com.acme.web;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;

@RestController
public class CalcController {
    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/calc")
    public Object calc(@RequestParam("expr") String expr) {
~>        Expression e = parser.parseExpression(expr);
        return e.getValue();
    }

    @PostMapping("/filter")
    public Object filter(HttpServletRequest request) {
        String rule = request.getParameter("rule");
        String full = "#root.?[" + rule + "]";
~>        return parser.parseExpression(full).getValue(items());
    }

    @GetMapping("/inline")
    public Object inline(HttpServletRequest request) {
~>        return new SpelExpressionParser().parseExpression(
                request.getHeader("X-Expr")).getValue();
    }

    private Object items() {
        return null;
    }
}
