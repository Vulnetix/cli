package boot;

import org.eclipse.jetty.server.Server;

public class Launcher {
    public static void main(String[] args) throws Exception {
        Server server = new Server(8080);
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> System.out.println("bye")));
        if (args.length == 0) {
            System.exit(2);
        }
    }
}
