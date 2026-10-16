package com.acme.kyc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Onboarding {
    private static final Logger LOGGER = LoggerFactory.getLogger(Onboarding.class);

    public void start(Applicant applicant) {
        LOGGER.info("Collecting SSN and date of birth for applicant {}", applicant.getId());
        LOGGER.info("has passport: {}", applicant.hasPassport());
        LOGGER.debug("ssn masked: {}", applicant.getSsnMasked());
        System.out.println("Please enter your passport number");
    }
}
