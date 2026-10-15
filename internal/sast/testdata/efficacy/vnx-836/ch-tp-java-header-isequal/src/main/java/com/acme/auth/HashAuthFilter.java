package com.acme.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.servlet.http.HttpServletRequest;

public class HashAuthFilter {
    private final UserRepository users;

    public HashAuthFilter(UserRepository users) {
        this.users = users;
    }

    public boolean authenticate(HttpServletRequest request) {
        User user = users.findByName(request.getHeader("X-User"));
        String supplied = request.getHeader("X-Password-Hash");
        if (user == null || supplied == null) {
            return false;
        }
~>        return MessageDigest.isEqual(user.getPasswordHash().getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@),
                supplied.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
    }
}
