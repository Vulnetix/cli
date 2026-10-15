package com.acme.auth;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class LoginService {
    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    public void login(Credentials c) {
~>        log.debug("User {} logging in with password {}", c.getUsername(), c.getPassword());
~>        LOG.warn("client secret: " + @@sample:c[o]nf[i]g[.][g]et[C]li[e]nt[S]ec[r]et@@());
    }
}
