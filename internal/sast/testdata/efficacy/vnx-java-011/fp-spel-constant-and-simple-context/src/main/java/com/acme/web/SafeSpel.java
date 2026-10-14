package com.acme.web;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.web.bind.annotation.*;

@RestController
public class SafeSpel {
    private static final String PRICE_RULE = "price * quantity";
    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/total")
    public Object total(@RequestParam String currency) {
        Object v = parser.parseExpression(PRICE_RULE).getValue(order());
        Object w = parser.parseExpression("items.size()").getValue(order());
        return v;
    }

    @GetMapping("/prop")
    public Object prop(@RequestParam String field) {
        SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return parser.parseExpression(field).getValue(ctx, order());
    }

    private Object order() {
        return null;
    }
}
