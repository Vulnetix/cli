package com.acme.user;

import java.util.Base64;

public class UserDao {
    public void save(User user, String rawPassword) {
        byte[] raw = rawPassword.getBytes();
~>        String stored = Base64.getEncoder().encodeToString(raw);
        jdbc.update("UPDATE users SET pw = ? WHERE id = ?", stored, user.getId());
    }

    public String export(User user) {
~>        return Base64.getEncoder().encodeToString(
            user.getPassword().getBytes());
    }
}

class Exporter {
    String hex(char[] adminPassword) {
~>        return java.util.HexFormat.of().formatHex(new String(adminPassword).getBytes());
    }
}
