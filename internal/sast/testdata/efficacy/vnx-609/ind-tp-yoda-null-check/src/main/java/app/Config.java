package app;

import java.util.Properties;

public class Config {
    private Properties props;
    private final Object lock = new Object();

    public Properties props() {
        if (null == props) {
~>            synchronized (lock) {
                if (null == props) {
                    props = load();
                }
            }
        }
        return props;
    }

    private Properties load() { return new Properties(); }
}
