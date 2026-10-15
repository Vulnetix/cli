package com.acme.clinic;

import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class AdmissionService {
    private static final Logger log = LoggerFactory.getLogger(AdmissionService.class);

    public void admit(Patient patient) {
        String className = patient.getClass().getSimpleName();
        log.info("admitting {} of type {}", patient.getId(), className);
~>        log.debug("patient {} dob {}", patient.getId(), patient.getDob());
~>        LoggerFactory.getLogger("audit").info("mrn={}", patient.getMrn());
    }
}
