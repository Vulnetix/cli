import java.util.logging.Logger;

public class App {
    private static final Logger log = Logger.getLogger("app");
    public static void main(String[] args) {
~>        log.info("Environment: " + System.getenv());
    }
}
