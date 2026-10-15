package com.acme.invite;

public final class InviteCodes {
    private InviteCodes() {}

    public static String code(String userId) {
~>        final var r = new java.util.Random(userId.hashCode() * 31L);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            sb.append((char) ('A' + r.nextInt(26)));
        }
        return sb.toString();
    }
}
