package com.example.jobs;

public class Runner {
    public void go(Runnable task) {
        Thread worker = new Thread(task);
        worker.start();
        new Thread(task).start();
        Runnable r = () -> System.out.println("inline");
        r.run();
        task.run();
        Thread current = Thread.currentThread();
        current.setName("main-runner");
    }
}
