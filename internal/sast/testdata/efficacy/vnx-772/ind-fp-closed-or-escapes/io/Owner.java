package io;

import java.io.*;
import java.net.*;

public class Owner {
    private InputStream stream;

    public String d(String path) throws IOException {
        FileReader fr = new FileReader(path);
        try {
            return new BufferedReader(fr).readLine();
        } finally {
            fr.close();
        }
    }

    public Socket open(String h, int p) throws IOException {
        Socket s = new Socket(h, p);
        return s;
    }

    public void keep(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        this.stream = in;
    }

    public void serve(int port) throws IOException {
        ServerSocket ss = new ServerSocket(port);
        while (true) {
            Socket c = ss.accept();
            handle(c);
        }
    }

    public String mem() {
        ByteArrayInputStream b = new ByteArrayInputStream(new byte[2]);
        Scanner sc = new Scanner(System.in);
        return sc.nextLine();
    }
}
