package com.acme.core;

import com.google.common.collect.Maps;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Constants {

    public enum Feature { BILLING, EXPORT, AUDIT }

~>    public final static ConcurrentHashMap<String, Handler> HANDLERS =
            new ConcurrentHashMap<>();

~>    public static final List<String> ALLOWED_HOSTS = Arrays.asList("api.acme.com", "cdn.acme.com");

~>    public static final EnumSet<Feature> ENABLED = EnumSet.of(Feature.BILLING, Feature.EXPORT);

~>    public static final SimpleDateFormat ISO_DAY = new SimpleDateFormat("yyyy-MM-dd");

~>    public static final Date EPOCH = new Date(0L);

~>    public static final StringBuilder BANNER = new StringBuilder("acme");

~>    public static final Map<String, Integer> LIMITS = Maps.newHashMap();

    protected Constants() {
    }
}
