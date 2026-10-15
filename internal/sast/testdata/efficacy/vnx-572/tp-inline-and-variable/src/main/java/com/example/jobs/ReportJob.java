package com.example.jobs;

public class ReportJob {
    private final Runnable task;

    public ReportJob(Runnable task) {
        this.task = task;
    }

    public void launch() {
~>        new Thread(task, "report").run();
    }

    public void launchNamed() {
        Thread worker = new Thread(task);
        worker.setDaemon(true);
~>        worker.run();
    }

    public void launchVirtual() {
        var t = Thread.ofVirtual().unstarted(task);
~>        t.run();
    }
}
