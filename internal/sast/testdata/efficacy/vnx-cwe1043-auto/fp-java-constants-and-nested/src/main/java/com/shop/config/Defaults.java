package com.shop.config;

public final class Defaults {
    public static final Duration TIMEOUT = Duration.ofSeconds(5);
    public static final Duration RETRY = Duration.ofSeconds(1);
    public static final Charset CHARSET = StandardCharsets.UTF_8;
    public static final Locale LOCALE = Locale.UK;
    public static final ZoneId ZONE = ZoneId.of("UTC");
    public static final Pattern SKU = Pattern.compile("[A-Z]{3}-\\d+");
    public static final List<String> CURRENCIES = List.of("GBP", "EUR");
    public static final Map<String, String> ALIASES = Map.of();
    private static final Logger LOG = LoggerFactory.getLogger(Defaults.class);
    static final Set<String> RESERVED = Set.of("admin");
    public static final BigDecimal MIN = BigDecimal.ONE;
    public static final URI HOME = URI.create("https://shop.example");

    private Client client;
    private Cache cache;
    private Router router;
    private Metrics metrics;
    private Tracer tracer;
    private Pool pool;

    static class Holder {
        private Client client;
        private Cache cache;
        private Router router;
        private Metrics metrics;
        private Tracer tracer;
        private Pool pool;
    }
}
