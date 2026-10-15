package app;

import org.springframework.beans.factory.annotation.Value;

public class Settings {
    @Value("${db.password}")
    private String password;

    public void apply(javax.sql.DataSource ds, String secret) {
        ((@@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][d]bc[p]2[.][B]as[i]cD[a]ta[S]ou[r]ce@@) ds).setPassword(secret);
    }
}
