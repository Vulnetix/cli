package net;

import java.io.*;
import java.net.Socket;

public class Banner {
    public String read(String host, int port) throws IOException {
~>        Socket socket = new Socket(host, port);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        return in.readLine();
    }
}
