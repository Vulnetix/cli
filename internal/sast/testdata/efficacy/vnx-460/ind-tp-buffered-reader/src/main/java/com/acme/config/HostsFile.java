package com.acme.config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class HostsFile {
    public static List<String> read(File file) throws IOException {
        List<String> hosts = new ArrayList<>();
~>        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            hosts.add(parseHost(line));
        }
        reader.close();
        return hosts;
    }
}
