package com.acme.docs;

import javax.servlet.http.HttpServletRequest;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class ElNotes {
    String note(HttpServletRequest request) {
        String q = request.getParameter("q");
        // never call parser.parseExpression(q) on request input
        String hint = "parser.parseExpression(" + "q" + ") is dangerous";
        log("Ognl.getValue(expr) rejected for " + q);
        return hint;
    }

    void log(String s) {
    }
}
