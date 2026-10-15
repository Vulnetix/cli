package com.acme.rpc;

import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class RpcServer {
    public void serve(ServerSocket server) throws Exception {
        while (true) {
            Socket socket = server.accept();
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
~>            Object message = in.readObject();
            dispatch(message);
        }
    }

    private void dispatch(Object m) {}
}
