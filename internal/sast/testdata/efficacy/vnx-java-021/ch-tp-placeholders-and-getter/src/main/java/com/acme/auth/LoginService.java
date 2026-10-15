package com.acme.auth;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class LoginService {
    private static final Logger logger = LoggerFactory.getLogger(LoginService.class);

    public boolean login(String user, String password) {
~>        logger.info("Connecting with user={} password={}", user, password);
        return check(user, password);
    }

    public void failed(Credentials creds) {
~>        logger.warn("Login failed for {} using {}", @@sample:c[r]ed[s][.]g[e]tU[s]er[n]am[e]@@(), @@sample:c[r]ed[s][.]g[e]tP[a]ss[w]or[d]@@());
    }

    private boolean check(String u, String p) {
        return false;
    }
}
