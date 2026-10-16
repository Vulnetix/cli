package com.acme.watch;

public class Reporter {
    public void report(Runnable task) throws InterruptedException {
        Thread t = new Thread(task, "report");
        // Do not call t.run() here: it would block the caller.
        t.start();
        t.join();
        String msg = "use start() rather than worker.run()";
        System.out.println(msg);
    }
}
