package com.shop.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;

public class Votes {
~>    public static final String TOKEN_KEY = @@sample:T[e]xt[C]od[e]c[.][B]AS[E]64[.]en[c]od[e]@@("victory");

    public Object read(String token) {
        return Jwts.parser().setSigningKey(TOKEN_KEY).parseClaimsJws(token);
    }
}
