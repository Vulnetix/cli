package com.shop.io;

import java.io.BufferedReader;
import java.io.IOException;

public class BodyReader {

    public static String read(BufferedReader reader) throws IOException {
        String body = "";
        String line;
        while ((line = reader.readLine()) != null)
        {
            if (line.isEmpty()) {
                continue;
            }
~>            body = body + line + "\n";
        }
        return body;
    }
}
