package com.acme.rpc;

import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.net.Socket;

public class SafeRpcServer {
    public Object read(Socket socket) throws Exception {
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.rpc.dto.*;java.base/*;!*"));
        return in.readObject();
    }
}
