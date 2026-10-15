package com.shop.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]j[w]t[.][J]wt[D]ec[o]de[r]@@;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]j[w]t[.][N]im[b]us[J]wt[D]ec[o]de[r]@@;

public class SecurityConfig {
    @Value("${idp.jwks-uri}")
    private String jwksUri;

    @Bean
    JwtDecoder jwtDecoder() {
~>        return NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
    }
}
