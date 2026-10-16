package com.acme;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class Customer {
    private Long id;
    private UUID uuid;
    private String email;
    private String name;
    private String phone;
    private BigDecimal balance;
    private Instant createdAt;
    private Instant updatedAt;
    private List<String> tags;
    private Boolean active;
    private Integer loyalty;
    private Double score;
    private Address address;
    private Account account;
    private static final Logger LOG = null;
    private static Registry registry1, registry2, registry3, registry4, registry5, registry6;
}
