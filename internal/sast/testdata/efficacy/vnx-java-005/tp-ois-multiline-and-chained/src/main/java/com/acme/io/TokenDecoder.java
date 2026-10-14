package com.acme.io;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.util.Base64;

public class TokenDecoder {
    public Object decode(String b64token) throws Exception {
        try (ObjectInputStream ois =
                new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(b64token)))) {
~>            return ois.readObject();
        }
    }

    public Object receive(Socket socket) throws Exception {
~>        return new ObjectInputStream(socket.getInputStream()).readObject();
    }
}
