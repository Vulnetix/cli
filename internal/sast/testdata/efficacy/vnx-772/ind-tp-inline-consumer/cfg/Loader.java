package cfg;

import java.io.*;
import java.util.Properties;

public class Loader {
    public Properties load(String path) throws IOException {
        Properties props = new Properties();
~>        props.load(new FileInputStream(path));
        return props;
    }

    public long lines(String p) throws IOException {
~>        Stream<String> s = Files.lines(Paths.get(p));
        return s.count();
    }
}
