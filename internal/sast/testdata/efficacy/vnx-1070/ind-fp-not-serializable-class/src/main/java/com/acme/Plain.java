package com.acme;
import java.io.Serializable;
import java.net.Socket;
import java.util.Optional;
class Token implements Serializable {
    private String value;
}
public class Plain {
    private Socket socket;
    private Optional<String> name;
    private Thread thread;
}
