package com.acme;

import java.time.Duration;
import org.springframework.context.annotation.Bean;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]j[w]t[.]@@*;

public class JwtConfig {
    @Bean
    JwtDecoder jwtDecoder(String jwkSetUri) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
~>        @@sample:O[A]ut[h]2T[o]ke[n]Va[l]id[a]to[r]@@<Jwt> validator = new JwtTimestampValidator(Duration.ofDays(30));
        decoder.setJwtValidator(validator);
        return decoder;
    }
}
