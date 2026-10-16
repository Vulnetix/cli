package com.acme;
import java.io.Serializable;
import java.net.Socket;
import java.util.Optional;
import java.util.logging.Logger;
public class Session implements Serializable {
    private static final long serialVersionUID = 1L;
    private String user;
~>    private Socket socket;
~>    protected Optional<String> nickname = Optional.empty();
~>    public volatile Thread refresher;
~>    @Deprecated private Logger auditLog = Logger.getLogger("audit");
    private transient Socket spare;
}
