package com.acme.config;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class Policy {
~>    public static final Date LICENSE_EXPIRY = new Date(1893456000000L);
~>    public static final List<String> SCOPES = Arrays.asList("read", "write");
~>    public static final StringBuilder BANNER = new StringBuilder("ACME");
}
