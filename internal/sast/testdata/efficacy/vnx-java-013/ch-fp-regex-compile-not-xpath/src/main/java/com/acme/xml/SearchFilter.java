package com.acme.xml;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;

public class SearchFilter {
    private final RuleEngine rules = new RuleEngine();

    public List<String> apply(HttpServletRequest request, List<String> names) {
        String q = request.getParameter("q");
        Pattern p = Pattern.compile(Pattern.quote(q));
        boolean ok = rules.evaluate(request.getParameter("rule"));
        return names.stream().filter(n -> ok && p.matcher(n).find()).collect(Collectors.toList());
    }

    static class RuleEngine {
        boolean evaluate(String r) {
            return r != null;
        }
    }
}
