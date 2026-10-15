package app;

import java.net.URLDecoder;

public class Legacy {
    String decode(String raw) {
~>        return URLDecoder.decode(raw);
    }

    void pause(Thread worker) {
~>        worker.suspend();
~>        worker.resume();
    }

    Object make(Class<?> type) throws Exception {
~>        Double d = new Double(1.5);
~>        return type.newInstance();
    }
}
