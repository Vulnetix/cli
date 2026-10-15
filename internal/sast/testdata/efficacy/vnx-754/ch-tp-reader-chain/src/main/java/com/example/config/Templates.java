package com.example.config;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class Templates {
    public String read(String name) {
        BufferedReader r = new BufferedReader(new InputStreamReader(
~>                getClass().getResourceAsStream("/templates/" + name), @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
        return r.lines().collect(Collectors.joining("\n"));
    }
}
