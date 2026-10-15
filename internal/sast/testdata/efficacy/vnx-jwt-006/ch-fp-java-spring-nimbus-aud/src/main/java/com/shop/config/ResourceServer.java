package com.shop.config;

import java.util.List;
import org.springframework.context.annotation.Bean;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]c[o]re[.]De[l]eg[a]ti[n]gO[A]ut[h]2T[o]ke[n]Va[l]id[a]to[r]@@;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]j[w]t[.][J]wt[C]la[i]mN[a]me[s]@@;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]j[w]t[.][J]wt[C]la[i]mV[a]li[d]at[o]r@@;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]j[w]t[.][J]wt[D]ec[o]de[r]@@;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]j[w]t[.][J]wt[V]al[i]da[t]or[s]@@;
import @@sample:o[r]g[.][s]pr[i]ng[f]ra[m]ew[o]rk[.]se[c]ur[i]ty[.]oa[u]th[2][.]j[w]t[.][N]im[b]us[J]wt[D]ec[o]de[r]@@;

public class ResourceServer {
    @Bean
    JwtDecoder jwtDecoder(String jwksUri, String issuer) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
        decoder.setJwtValidator(new @@sample:D[e]le[g]at[i]ng[O]Au[t]h2[T]ok[e]nV[a]li[d]at[o]r@@<>(
            JwtValidators.createDefaultWithIssuer(issuer),
            new JwtClaimValidator<List<String>>(JwtClaimNames.AUD, aud -> aud.contains("orders-api"))));
        return decoder;
    }
}
