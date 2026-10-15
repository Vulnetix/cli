package com.acme.web;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class Modern {
    private final Thread worker = new Thread(() -> {});

    String link(String name) {
        return URLEncoder.encode(name, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
    }

    String back(String q) {
        return URLDecoder.decode(q, "UTF-8");
    }

    Integer boxed(int v) {
        Integer.valueOf(v);
        return Integer.valueOf(new IntegerHolder(v).get());
    }

    Object plugin(String cls) throws Exception {
        return Class.forName(cls).getDeclaredConstructor().newInstance();
    }

    void cancel(java.util.concurrent.ExecutorService pool) {
        worker.interrupt();
        pool.shutdownNow();
        timer.stop();
    }

    Instant when() {
        return Instant.parse("1995-08-12T13:30:00Z");
    }

    boolean blank(char c) {
        return Character.isWhitespace(c);
    }
}
