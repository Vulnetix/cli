package com.acme.billing;

import java.io.IOException;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class PaymentService {
    private static final Logger log = LoggerFactory.getLogger(PaymentService.class);

    public void charge(Payment p) {
        try {
            gateway.charge(p);
        } catch (IOException e) {
            log.error("charge failed for {}", p.id(), e);
            throw new PaymentException("charge failed", e);
        }
    }

    public boolean refund(Payment p) {
        try {
            gateway.refund(p);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public void ping() {
        try { gateway.ping(); } catch (IOException e) { metrics.increment("ping.fail"); }
    }
}
