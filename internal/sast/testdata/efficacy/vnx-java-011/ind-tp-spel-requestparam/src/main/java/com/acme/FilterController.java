package com.acme;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.*;

@RestController
public class FilterController {
    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/calc")
    public Object calc(@RequestParam("expr") String expr) {
~>        return parser.parseExpression(expr).getValue();
    }
}
