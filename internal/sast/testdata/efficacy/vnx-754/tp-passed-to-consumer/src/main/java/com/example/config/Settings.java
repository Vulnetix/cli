package com.example.config;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import org.apache.commons.io.IOUtils;

public class Settings {
    private final Properties props = new Properties();

    public void init() throws IOException {
~>        props.load(Settings.class.getClassLoader().getResourceAsStream("app.properties"));
~>        BufferedReader r = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream("/words.txt"), @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@));
~>        String sql = IOUtils.toString(getClass().getResourceAsStream("/schema.sql"), @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
    }
}
