package com.acme.reset;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class ResetService {
    public String start(String email) {
~>        String resetToken = UUID.nameUUIDFromBytes(email.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@)).toString();
        return resetToken;
    }
}
