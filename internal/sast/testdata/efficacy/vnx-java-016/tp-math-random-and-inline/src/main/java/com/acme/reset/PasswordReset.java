package com.acme.reset;

public class PasswordReset {
    public String createResetCode() {
~>        long code = (long) (Math.random() * 1_000_000L);
        return String.format("%06d", code);
    }

    public String temporaryPassword() {
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < 12; i++) {
~>            password.append((char) ('a' + new java.util.Random().nextInt(26)));
        }
        return password.toString();
    }

    String salt() {
~>        String salt = String.valueOf(Math.random()).substring(2);
        return salt;
    }
}
