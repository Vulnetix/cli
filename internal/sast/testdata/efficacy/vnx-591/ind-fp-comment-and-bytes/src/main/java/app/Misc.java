package app;

import java.nio.charset.StandardCharsets;

public class Misc {
    // Do not do: String p = new String(console.readPassword());
    String note = "new String(console.readPassword()) is bad";

    String decode(byte[] body) {
        return new String(body, StandardCharsets.UTF_8);
    }

    String fromChars(char[] letters) {
        return String.valueOf(letters);
    }
}
