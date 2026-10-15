package com.acme;

import java.io.Serializable;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;

public class Order implements Serializable {
    private String id;
    private BigDecimal total;
    private Instant placed;
    private List<String> lines;
    private ThreadLocalRandomSeed seed;
    private InputStreamFactory streamFactory;
}
