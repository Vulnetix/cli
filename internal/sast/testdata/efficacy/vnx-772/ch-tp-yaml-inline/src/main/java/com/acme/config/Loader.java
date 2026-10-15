package com.acme.config;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;

public class Loader {
    public Map<String, Object> load(String path) throws FileNotFoundException {
        Yaml yaml = new Yaml();
~>        return yaml.load(new FileInputStream(path));
    }
}
