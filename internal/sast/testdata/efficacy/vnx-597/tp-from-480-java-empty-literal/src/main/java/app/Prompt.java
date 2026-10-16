package app;

import java.util.Scanner;

public class Prompt {
    void loop(Scanner in) {
        String cmd = in.nextLine();
~>        while (cmd != "quit") {
~>            if (cmd == "") {
                continue;
            }
            cmd = in.nextLine();
        }
    }
}
