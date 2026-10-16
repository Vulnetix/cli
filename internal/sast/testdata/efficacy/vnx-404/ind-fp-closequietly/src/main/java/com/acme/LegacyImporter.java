package com.acme;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import org.apache.commons.io.IOUtils;

public class LegacyImporter {

    public Properties read(String path) throws IOException {
        Properties props = new Properties();
        FileInputStream in = new FileInputStream(path);
        props.load(in);
        IOUtils.closeQuietly(in);
        return props;
    }
}
