package app;

import java.io.Console;
import java.util.Arrays;
import javax.crypto.spec.PBEKeySpec;

public class Safe {
    void run(Console console) {
        char[] pw = console.readPassword("Password: ");
        try {
            PBEKeySpec spec = new PBEKeySpec(pw, salt, 210000, 256);
            derive(spec);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }
}
