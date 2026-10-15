package app;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class Service {
    private final Server server = new Server();

    String decode(String raw) {
        return URLDecoder.decode(raw, @@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
    }

    void shutdown() {
        server.stop();
        server.resume();
        Integer n = Integer.valueOf(5);
    }

    Object make(Class<?> type) throws Exception {
        return type.getDeclaredConstructor().newInstance();
    }

    static class Server {
        void stop() {}
        void resume() {}
    }
}
