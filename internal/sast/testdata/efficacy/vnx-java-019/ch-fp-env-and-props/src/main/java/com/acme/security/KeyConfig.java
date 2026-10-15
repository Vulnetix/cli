package com.acme.security;

import @@sample:c[o]m[.][a]ut[h]0[.][j]wt[.]al[g]or[i]th[m]s[.][A]lg[o]ri[t]hm@@;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;

public class KeyConfig {
    @Value("${jwt.secret}")
    private String jwtSecret;

    private final Properties props;

    public KeyConfig(Properties props) {
        this.props = props;
    }

    public Algorithm algorithm() {
        String secret = System.getenv("JWT_SECRET");
        return Algorithm.HMAC256(secret);
    }

    public Algorithm springAlgorithm() {
        return Algorithm.HMAC512(jwtSecret);
    }

    public SecretKeySpec dataKey() {
        return new SecretKeySpec(Base64.getDecoder().decode(props.getProperty("data.key")), "AES");
    }
}
