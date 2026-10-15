package com.acme.auth;

import java.util.StringTokenizer;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class ExpressionParser {
    private static final Logger log = LoggerFactory.getLogger(ExpressionParser.class);

    public void parse(String input, Person secretary) {
        StringTokenizer tokenizer = new StringTokenizer(input, ",");
        log.debug("Parsing {} with {}", input, tokenizer);
        log.info("Meeting booked by {}", secretary.getName());
        log.info("Password reset link sent to {}", secretary.getEmail());
        log.debug("Loaded {} tokens", tokenizer.countTokens());
    }
}
