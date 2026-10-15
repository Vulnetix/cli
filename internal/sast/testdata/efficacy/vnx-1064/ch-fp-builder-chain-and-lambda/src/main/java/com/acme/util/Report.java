package com.acme.util;

public final class Report {
    Summary build(Row r) {
        Summary s = Summary.of(r.a(), r.b(), r.c(), r.d(), r.e(), r.f(), r.g(), r.h());
        Formatter f = (a, b, c, d, e, g, h, k) -> a + b;
        log.info("{} {} {} {} {} {} {} {}", 1, 2, 3, 4, 5, 6, 7, 8);
        return render(s,
                1, 2, 3, 4,
                5, 6, 7, 8);
    }
}
