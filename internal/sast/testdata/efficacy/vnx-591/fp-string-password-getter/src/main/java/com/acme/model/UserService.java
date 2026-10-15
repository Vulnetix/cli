package com.acme.model;

import java.nio.charset.StandardCharsets;

public class UserService {
    String hashFor(User user, byte[] salt) {
        String stored = user.getPassword();
        String decoded = new String(salt, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        return stored + decoded;
    }

    String banner(Config cfg) {
        return String.valueOf(cfg.getPasswordPolicyLength());
    }
}
