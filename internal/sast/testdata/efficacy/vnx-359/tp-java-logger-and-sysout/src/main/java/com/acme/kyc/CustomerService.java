package com.acme.kyc;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class CustomerService {
    private static final Logger log = LoggerFactory.getLogger(CustomerService.class);

    public void onboard(Customer customer) {
~>        log.info("Onboarding {} with SSN {}", customer.getName(), customer.getSsn());
~>        System.out.println("DOB: " + customer.getDateOfBirth());
        String passport = customer.getPassportNumber();
~>        LOGGER.debug("passport=" + customer.passportNumber + " licence=" + customer.driversLicenseNumber);
    }
}
