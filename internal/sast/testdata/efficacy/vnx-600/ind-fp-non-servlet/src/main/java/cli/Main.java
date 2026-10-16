package cli;

public class Main {
    public static void main(String[] argv) {
        int port = Integer.parseInt(argv[0]);
        run(port);
    }

    static int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
