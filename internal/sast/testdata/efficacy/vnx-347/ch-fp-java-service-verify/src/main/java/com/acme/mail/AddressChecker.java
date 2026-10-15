package com.acme.mail;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class AddressChecker {
    private static final Logger log = LoggerFactory.getLogger(AddressChecker.class);
    private final MailService mailService;

    public AddressChecker(MailService mailService) {
        this.mailService = mailService;
    }

    public void warm(String address) {
        try {
            mailService.verify(address);
        } catch (Exception e) {
            log.debug("address check skipped", e);
        }
    }
}
