package com.acme;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.web.bind.annotation.*;

@RestController
public class SafeEval {
    @GetMapping("/prop")
    public Object prop(@RequestParam("name") String name) {
        SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        Expression e = new SpelExpressionParser().parseExpression("title");
        return e.getValue(ctx, new Object());
    }
}
