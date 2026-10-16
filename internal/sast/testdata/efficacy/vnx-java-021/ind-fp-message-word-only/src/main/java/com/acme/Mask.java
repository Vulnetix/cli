package com.acme;
import org.slf4j.*;
public class Mask {
    private static final Logger log = LoggerFactory.getLogger(Mask.class);
    void rotate(int count) {
        log.info("rotated {} entries", count);
        log.info("Password reset email sent");
    }
}
