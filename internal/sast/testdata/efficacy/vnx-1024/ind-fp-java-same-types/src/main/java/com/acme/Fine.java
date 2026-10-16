package com.acme;

import java.util.Objects;

public class Fine {
    private Long ownerId;
    private String level;

    boolean a() { return ownerId.equals(0L); }
    boolean b() { return level.equals("1"); }
    boolean c() { return Objects.equals(level, "x"); }
    boolean d() { return "5".equals(level); }
    String e() { return "level.equals(1) never fires"; }
    // ownerId.equals(0)
}
