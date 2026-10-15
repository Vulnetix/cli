package app;

public class Notify {
    void send(String to, String msg) {
        if (to != null)
            mailer.send(to,
                    msg);
        log.info("done");
        for (int i = 0; i < 3; i++)
            retry(to, msg,
                  i);
        return;
    }
}
