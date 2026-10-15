package com.acme.kyc;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class KycService {
    private static final Logger LOGGER = LoggerFactory.getLogger(KycService.class);

    public void verify(Person person) {
~>        LOGGER.info("SSN {}", person.getSocialSecurityNumber());
~>        LOGGER.debug("dob=" + person.getDateOfBirth() + ", ssn=" + mask(person.getSsn()));
~>        System.out.printf("tax id %s%n", person.getTaxId());
    }
}
