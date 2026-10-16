package com.acme;
import java.util.logging.Logger;
public class Tok {
    private static final Logger LOGGER = Logger.getLogger("tok");
    void h(String accessToken) {
~>        LOGGER.warning("bad request, token " + accessToken);
    }
}
