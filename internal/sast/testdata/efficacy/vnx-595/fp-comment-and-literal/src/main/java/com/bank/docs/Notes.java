package com.bank.docs;

public class Notes {
    // Integer a, Integer b: never write a == b
    static final String TIP = "value == new Integer(0) is always false";

    void explain(Integer a, Integer b, org.slf4j.Logger log) {
        log.info("compare with a == b only for primitives");
        /* a == b compares references */
    }
}
