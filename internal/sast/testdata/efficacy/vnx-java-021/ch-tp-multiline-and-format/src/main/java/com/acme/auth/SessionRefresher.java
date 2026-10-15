package com.acme.auth;

import @@sample:l[o]mb[o]k[.][e]xt[e]rn[.]sl[f]4j[.]Sl[f]4j@@;

@Slf4j
public class SessionRefresher {
    public void refresh(String account, String refreshToken, String dbPassword) {
~>        log.info("Refreshing session for {} with {}",
                 account,
                 refreshToken);
~>        log.debug(String.format("connecting to db with %s", dbPassword));
        String jwtToken = mint(account);
~>        log.debug("Issued JWT " + jwtToken);
    }

    private String mint(String a) {
        return a;
    }
}
