package web;

import java.util.Objects;

public class Good {
    boolean a(String role) { return "admin".equals(role); }
    boolean b(String role) { return Objects.equals(role, "root"); }
    boolean c(String role) { return role == null || role.isEmpty(); }
    boolean d(char c) { return c == 'a'; }
    boolean e(String s) { return s.equalsIgnoreCase("yes"); }
    // if (role == "admin") is wrong
    String doc = "role == \"admin\"";
}
