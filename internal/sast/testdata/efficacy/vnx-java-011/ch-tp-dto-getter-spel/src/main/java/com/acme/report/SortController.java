package com.acme.report;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

public class SortController {
    private static final ExpressionParser PARSER = new SpelExpressionParser();

    @PostMapping("/report/sort")
    public Object sort(@RequestBody SortRequest order) {
~>        return PARSER.parseExpression(order.getSortExpression()).getValue(order);
    }
}
