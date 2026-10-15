package com.example;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class Download {
    String resolve(String file) {
        String name = URLDecoder.decode(file, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        if (name.contains("..")) {
            throw new IllegalArgumentException("bad name");
        }
        return name;
    }

    String twice(String file) {
        if (file.contains("..")) {
            throw new IllegalArgumentException("bad name");
        }
        String name = URLDecoder.decode(file, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
        if (name.contains("..")) {
            throw new IllegalArgumentException("bad name");
        }
        return name;
    }
}
