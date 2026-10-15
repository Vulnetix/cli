package com.acme.rules;

import java.util.List;
import java.util.stream.Collectors;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FilterController {
    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/products/filter")
    public List<Product> filter(@RequestParam String predicate, List<Product> all) {
        String spel = "price > 0 and " + predicate;
~>        Expression exp = parser.parseExpression(spel);
        return all.stream()
            .filter(p -> Boolean.TRUE.equals(exp.getValue(new StandardEvaluationContext(p), Boolean.class)))
            .collect(Collectors.toList());
    }
}
