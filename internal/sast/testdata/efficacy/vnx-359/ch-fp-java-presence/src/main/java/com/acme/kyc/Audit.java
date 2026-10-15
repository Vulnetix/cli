package com.acme.kyc;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class Audit {
    private static final Logger log = LoggerFactory.getLogger(Audit.class);

    public void record(Person person) {
        log.debug("has passport: {}", person.getPassport() != null);
        log.info("SSN check passed for {}", person.getId());
        log.info("ssn {}", Masking.lastFour(person.getSsn()));
    }
}
