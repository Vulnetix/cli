package com.acme.io;

import java.io.IOException;
import java.net.Socket;
import java.util.zip.ZipFile;
import org.apache.commons.io.IOUtils;

public class Archive {
    public int entries(String path) throws IOException {
        ZipFile zip = new ZipFile(path);
        try {
            return zip.size();
        } finally {
            IOUtils.closeQuietly(zip);
        }
    }

    public void ping(String host) throws IOException {
        Socket socket = null;
        try {
            socket = new Socket(host, 7);
            socket.getOutputStream().write(1);
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }
}
