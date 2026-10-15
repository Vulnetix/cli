package com.shop.keys;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class ApiKeys {
    public String issue(String email) {
~>        String apiKey = UUID.nameUUIDFromBytes(email.getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@)).toString();
        return apiKey;
    }
}
